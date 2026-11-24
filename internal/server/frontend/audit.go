package frontend

import (
	"context"
	"log"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/server/audit"
)

// newHandlerAuditBudget builds the budget of UnauthenticatedAuditRowsPerMinute
// for a handler with the audit service svc and starts its background check
// (when the budget is on).
func newHandlerAuditBudget(o Options, svc *audit.Service) *auditBudget {
	var b *auditBudget
	b = newAuditBudget(o.UnauthenticatedAuditRowsPerMinute, o.now, func(dropped int, minute time.Time) {
		ctx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
		defer cancel()
		md := map[string]any{
			"dropped":           dropped,
			"minute":            minute.UTC().Format(time.RFC3339),
			"budget_per_minute": b.limit,
		}
		if err := svc.Log(ctx, nil, auditDroppedAction, md, netip.Addr{}); err != nil {
			log.Printf("frontend: audit: write %q failed: %v", auditDroppedAction, err)
		}
	})
	if b.limit > 0 {
		b.start(auditFlushInterval)
	}
	return b
}

// auditWriteTimeout bounds one audit write. The write does not run on the
// request's context, see audit.
const auditWriteTimeout = 5 * time.Second

// audit writes one entry to the audit log. It does nothing when o.Audit is
// nil. A write error is logged and never returned: the action the entry
// describes has already happened, and the handler has nothing better to do
// with the error than to carry on.
//
// actorUserID is the user who performed the action, or nil when nobody is
// logged in (a failed login, for example). action is one of the dotted
// lower-case names such as "auth.login.success" or "token.revoke".
// metadata must be encodable as JSON and must not contain secrets
// (passwords, raw tokens).
//
// The IP address is taken from r.RemoteAddr, the peer of the connection,
// and from nothing a client can set in a header. If RemoteAddr does not
// parse, the entry is written without an address.
//
// The write runs on a context detached from the request, limited to
// auditWriteTimeout, so that a client that hangs up cannot keep its own
// action out of the log.
func (o Options) audit(r *http.Request, actorUserID *int64, action string, metadata map[string]any) {
	if o.Audit == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), auditWriteTimeout)
	defer cancel()

	if err := o.Audit.Log(ctx, actorUserID, action, metadata, peerAddr(r.RemoteAddr)); err != nil {
		log.Printf("frontend: audit: write %q failed: %v", action, err)
	}
}

// auditOutsider is audit for a row that a request without a login causes
// at will (a failed login, a password-reset request). Such rows count
// against Options.UnauthenticatedAuditRowsPerMinute (auditBudget); a row
// over it is not written but counted. Nobody is logged in for such a row.
func (o Options) auditOutsider(r *http.Request, action string, metadata map[string]any) {
	if o.Audit == nil {
		return
	}
	if o.audits != nil && !o.audits.take() {
		return
	}
	o.audit(r, nil, action, metadata)
}

// auditDroppedAction is the action of the row that says how many rows of
// requests without a login were dropped in a minute.
const auditDroppedAction = "audit.unauthenticated.dropped"

// auditFlushInterval is how often the background check of auditBudget
// looks whether a minute with dropped rows has ended without a request
// since that would have written its summary.
const auditFlushInterval = 15 * time.Second

// auditBudget is the budget of Options.UnauthenticatedAuditRowsPerMinute,
// one per handler: at most limit rows per clock minute; the rows over it
// are counted, and when the minute has ended, write records their number
// in one row and one log line is written. The summary of a minute is
// written by the first row of a later minute or, without one, by the
// background check (start), and by close for the minute in progress.
type auditBudget struct {
	limit int // <= 0: no budget
	now   func() time.Time
	write func(dropped int, minute time.Time)

	mu      sync.Mutex
	minute  time.Time // start of the minute counted
	written int
	dropped int

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

func newAuditBudget(limit int, now func() time.Time, write func(dropped int, minute time.Time)) *auditBudget {
	if now == nil {
		now = time.Now
	}
	return &auditBudget{limit: resolveCount(limit, DefaultUnauthenticatedAuditRowsPerMinute), now: now, write: write}
}

// take reports whether one more row may be written now and counts it
// either way. A minute that has ended is closed first.
func (b *auditBudget) take() bool {
	b.mu.Lock()
	dropped, minute := b.turnLocked(b.now())
	ok := b.limit <= 0 || b.written < b.limit
	if ok {
		b.written++
	} else {
		b.dropped++
	}
	b.mu.Unlock()
	b.report(dropped, minute)
	return ok
}

// turnLocked starts counting a new minute whenever the clock is in another
// minute than the one counted (also after the clock stepped back), and
// returns the number of rows dropped in the minute that ended.
func (b *auditBudget) turnLocked(now time.Time) (dropped int, minute time.Time) {
	m := now.Truncate(time.Minute)
	if m.Equal(b.minute) {
		return 0, time.Time{}
	}
	dropped, minute = b.dropped, b.minute
	b.minute, b.written, b.dropped = m, 0, 0
	return dropped, minute
}

// flush writes the summary of a minute that has ended, if rows were dropped
// in it and no later row has written it yet.
func (b *auditBudget) flush() {
	b.mu.Lock()
	dropped, minute := b.turnLocked(b.now())
	b.mu.Unlock()
	b.report(dropped, minute)
}

// report writes the summary row and the log line of a minute with drops.
func (b *auditBudget) report(dropped int, minute time.Time) {
	if dropped == 0 {
		return
	}
	log.Printf("frontend: audit: %d audit rows of requests without a login dropped in the minute from %s "+
		"(frontend.unauthenticated_audit_rows_per_minute: %d)", dropped, minute.UTC().Format(time.RFC3339), b.limit)
	if b.write != nil {
		b.write(dropped, minute)
	}
}

// start runs the background check until close.
func (b *auditBudget) start(interval time.Duration) {
	b.stop, b.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(b.done)
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-b.stop:
				return
			case <-tick.C:
				b.flush()
			}
		}
	}()
}

// close ends the background check and writes the summary of the minute in
// progress, so that a count is not lost at shutdown.
func (b *auditBudget) close() {
	b.stopOnce.Do(func() {
		if b.stop != nil {
			close(b.stop)
			<-b.done
		}
		b.mu.Lock()
		dropped, minute := b.dropped, b.minute
		b.dropped = 0
		b.mu.Unlock()
		b.report(dropped, minute)
	})
}

// peerAddr extracts the IP address from a "host:port" peer address, or from
// a bare address. It returns the zero Addr when there is none. An
// IPv4-mapped IPv6 address is unmapped, so that an IPv4 peer is stored as
// IPv4. (A zone, as in fe80::1%eth0, does not reach the inet column: the
// database driver leaves it out.)
func peerAddr(remoteAddr string) netip.Addr {
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	if a, err := netip.ParseAddr(remoteAddr); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}
