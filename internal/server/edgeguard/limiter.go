package edgeguard

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Errors returned by Limiter.Acquire. LimitLabel maps them to metric labels.
var (
	ErrLimitTotal  = errors.New("edgeguard: total limit reached")
	ErrLimitTunnel = errors.New("edgeguard: per-tunnel limit reached")
	ErrLimitSource = errors.New("edgeguard: per-source limit reached")
)

// Budget is a total that several Limiters share, for example the limiters of
// the TCP edge and the HTTP edge, so that their connections together stay
// within one number. A slot held in any of the limiters counts. Limiters are
// attached with Limiter.SetBudget. A Budget is safe for concurrent use.
type Budget struct {
	max  int64
	used atomic.Int64
}

// NewBudget returns a budget of max slots. A max that is not positive is not
// enforced; the budget then only counts.
func NewBudget(max int) *Budget {
	return &Budget{max: int64(max)}
}

// Used returns the number of slots currently taken. It never exceeds the
// budget's max.
func (b *Budget) Used() int {
	return int(b.used.Load())
}

func (b *Budget) take() bool {
	for {
		n := b.used.Load()
		if b.max > 0 && n >= b.max {
			return false
		}
		if b.used.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (b *Budget) give() {
	b.used.Add(-1)
}

// Limiter bounds how many connections (or UDP flows) exist at the same time:
// in total, per tunnel, and per source within one tunnel.
//
// A slot counts a visitor (a connection or a flow) together with the tunnel
// stream opened for it until both are gone (see Slot): the stream can
// outlive the visitor.
type Limiter struct {
	maxTotal, maxPerTunnel, maxPerSource int
	budget                               *Budget // shared total, or nil

	mu       sync.Mutex
	total    int // slots held: by a visitor, or by a stream that is not gone yet
	visitors int // slots whose visitor is still there
	tunnels  map[string]*tunnelUse
}

type tunnelUse struct {
	n       int
	sources map[netip.Addr]int
}

// NewLimiter returns a Limiter. A limit that is not positive is not enforced.
func NewLimiter(maxTotal, maxPerTunnel, maxPerSource int) *Limiter {
	return &Limiter{
		maxTotal:     maxTotal,
		maxPerTunnel: maxPerTunnel,
		maxPerSource: maxPerSource,
		tunnels:      map[string]*tunnelUse{},
	}
}

// SetBudget makes every slot of the limiter count against b as well; a nil b
// leaves the limiter on its own. The limiter's own total keeps applying. Call
// it before the limiter is used.
func (l *Limiter) SetBudget(b *Budget) {
	l.budget = b
}

// Acquire reserves one slot for a connection from source to tunnel. On
// success the caller must call release when the connection ends; calling it
// more than once is harmless. release gives back the whole slot: Acquire is
// for connections that do not open a tunnel stream (see Take for those that
// do). On failure err is one of the ErrLimit values and nothing is held.
func (l *Limiter) Acquire(tunnel string, source netip.Addr) (release func(), err error) {
	s, err := l.Take(tunnel, source)
	if err != nil {
		return nil, err
	}
	return s.Release, nil
}

// Take reserves one slot for a visitor (a connection or a flow) from source
// to tunnel. On success the caller must call Release when the visitor is
// gone, and Hold for the tunnel stream it opens for the visitor (see Slot).
// On failure err is one of the ErrLimit values and nothing is held.
func (l *Limiter) Take(tunnel string, source netip.Addr) (*Slot, error) {
	src := SourceKey(source)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.maxTotal > 0 && l.total >= l.maxTotal {
		return nil, ErrLimitTotal
	}
	tu := l.tunnels[tunnel]
	if tu != nil {
		if l.maxPerTunnel > 0 && tu.n >= l.maxPerTunnel {
			return nil, ErrLimitTunnel
		}
		if l.maxPerSource > 0 && tu.sources[src] >= l.maxPerSource {
			return nil, ErrLimitSource
		}
	}
	if l.budget != nil && !l.budget.take() {
		return nil, ErrLimitTotal
	}
	if tu == nil {
		tu = &tunnelUse{sources: map[netip.Addr]int{}}
		l.tunnels[tunnel] = tu
	}
	l.total++
	l.visitors++
	tu.n++
	tu.sources[src]++

	s := &Slot{l: l, tunnel: tunnel, src: src}
	s.holders.Store(1) // the visitor
	return s, nil
}

// Slot is one slot of a Limiter, taken by Take: a place in the total (the
// limiter's own and the shared Budget), in the tunnel's count and in the
// count of the visitor's source address. All three belong to the visitor and
// to the tunnel stream that the edge opened for it, whichever is gone last.
//
// A stream outlives its visitor when the tunnel client keeps its side open
// after the edge closed its own: yamux keeps such a stream until the client
// closes it, the close timer resets it (five minutes) or the session ends,
// and the stream holds memory on the server until then. It was caused by the
// visitor's address on that tunnel, so it keeps counting against both: one
// address can keep at most the per-source limit of a tunnel's streams
// lingering, the same number it can hold as open connections. (The tunnel
// client's stream limits count a lingering stream as well.) Hold adds the
// stream as a holder; edgeguard.Retire gives it back when the stream is
// gone. Release gives back the visitor's hold.
type Slot struct {
	l       *Limiter
	tunnel  string
	src     netip.Addr
	visitor sync.Once
	holders atomic.Int32 // holders of the places: the visitor and streams
}

// Release records that the visitor is gone and gives back its hold on the
// slot; the places come back with the last hold. Calling it more than once
// is harmless.
func (s *Slot) Release() {
	s.visitor.Do(func() {
		s.l.visitorGone()
		s.drop()
	})
}

// Hold adds a holder of the slot's places, for the tunnel stream opened for
// the visitor, and returns the function that gives the hold back (calling it
// more than once is harmless). ok is false when nothing holds the places any
// more, because the visitor's Release and every earlier hold have been given
// back; the places are gone then and done does nothing.
func (s *Slot) Hold() (done func(), ok bool) {
	for {
		n := s.holders.Load()
		if n <= 0 {
			return func() {}, false
		}
		if s.holders.CompareAndSwap(n, n+1) {
			break
		}
	}
	var once sync.Once
	return func() { once.Do(s.drop) }, true
}

// drop gives back one hold on the slot; the last one gives the places back.
func (s *Slot) drop() {
	if s.holders.Add(-1) == 0 {
		s.l.release(s.tunnel, s.src)
	}
}

func (l *Limiter) visitorGone() {
	l.mu.Lock()
	l.visitors--
	l.mu.Unlock()
}

func (l *Limiter) release(tunnel string, src netip.Addr) {
	l.mu.Lock()
	l.total--
	if tu := l.tunnels[tunnel]; tu != nil {
		tu.n--
		if tu.sources[src]--; tu.sources[src] <= 0 {
			delete(tu.sources, src)
		}
		if tu.n <= 0 {
			delete(l.tunnels, tunnel)
		}
	}
	l.mu.Unlock()
	if l.budget != nil {
		l.budget.give()
	}
}

// Total returns the number of slots held: by a visitor, or by a tunnel
// stream that is not gone yet.
func (l *Limiter) Total() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

// Visitors returns the number of slots whose visitor (connection or flow)
// is still there. No limit counts visitors alone; it shows how many of the
// held slots are held only by streams that are not gone yet.
func (l *Limiter) Visitors() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.visitors
}

// LimitLabel returns the fixed metric status label for an error from Acquire.
func LimitLabel(err error) string {
	switch {
	case errors.Is(err, ErrLimitTotal):
		return "limit_total"
	case errors.Is(err, ErrLimitTunnel):
		return "limit_tunnel"
	case errors.Is(err, ErrLimitSource):
		return "limit_ip"
	}
	return "limit"
}

// SourceKey maps an address to the unit that per-source limits count: the
// address itself for IPv4 (including IPv4-mapped IPv6), the enclosing /64 for
// IPv6, because a single host usually controls a whole /64.
func SourceKey(addr netip.Addr) netip.Addr {
	addr = addr.Unmap().WithZone("")
	if addr.Is6() {
		if p, err := addr.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return addr
}

// ParseSource extracts the IP address from a "host:port" string as returned
// by net.Addr.String or found in http.Request.RemoteAddr. It returns the zero
// Addr when there is none; such sources then share one limit bucket.
func ParseSource(hostport string) netip.Addr {
	ap, err := netip.ParseAddrPort(hostport)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// SourceIP returns the address as the edges pass it on in stream headers and
// forwarding headers, or "" for the zero Addr: a peer of unknown address is
// reported as unknown, never as some other string.
func SourceIP(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}
