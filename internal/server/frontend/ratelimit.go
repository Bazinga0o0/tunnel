package frontend

import (
	"container/list"
	"crypto/sha256"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// rateLimiters holds the rate-limiter state of one handler (one call of
// New). The state lives in memory and is lost on restart.
type rateLimiters struct {
	loginAccount *rateLimiter // failed logins per typed address
	loginIP      *rateLimiter // failed logins per client
	logins       *rateLimiter // successful logins per address
	signupIP     *rateLimiter // sign-up attempts per client
	resetIP      *rateLimiter // password-reset requests per client
	resetAccount *rateLimiter // password-reset requests per typed address
	resetStored  *rateLimiter // reset links per stored address (silent, see issueReset)
	resend       *rateLimiter // verification mails per user
	userActions  *rateLimiter // mutating actions of the user area per user
	directory    *rateLimiter // requests to the directory API per client
	hashes       *hashBound   // password-hash work in flight per client
}

// resendInterval is the time between two verification mails a signed-in
// user can request.
const resendInterval = time.Minute

// newRateLimiters builds the limiters from the options (see the fields of
// Options for the defaults and the meaning of zero and negative values).
func newRateLimiters(o Options) *rateLimiters {
	now := o.now
	if now == nil {
		now = time.Now
	}
	maxKeys := resolveCount(o.RateLimitMaxKeys, DefaultRateLimitMaxKeys)
	loginWindow := resolveWindow(o.LoginFailureWindow, DefaultLoginFailureWindow)
	resetWindow := resolveWindow(o.ResetRequestWindow, DefaultResetRequestWindow)
	return &rateLimiters{
		// An account pushed out of this table gets a fresh set of guesses at
		// its password: when full, the table makes room by its failures
		// (evictingByFailures), not by age, and never refuses.
		loginAccount: newRateLimiter(resolveCount(o.LoginFailuresPerAccount, DefaultLoginFailuresPerAccount), loginWindow, maxKeys, now).
			evictingByFailures("of failed logins per account"),
		loginIP:      newRateLimiter(resolveCount(o.LoginFailuresPerIP, DefaultLoginFailuresPerIP), loginWindow, maxKeys, now),
		logins:       newRateLimiter(resolveCount(o.LoginsPerAccount, DefaultLoginsPerAccount), loginWindow, maxKeys, now),
		signupIP:     newRateLimiter(resolveCount(o.SignupsPerIP, DefaultSignupsPerIP), resolveWindow(o.SignupWindow, DefaultSignupWindow), maxKeys, now),
		resetIP:      newRateLimiter(resolveCount(o.ResetRequestsPerIP, DefaultResetRequestsPerIP), resetWindow, maxKeys, now),
		resetAccount: newRateLimiter(resolveCount(o.ResetRequestsPerAccount, DefaultResetRequestsPerAccount), resetWindow, maxKeys, now),
		resetStored:  newRateLimiter(resolveCount(o.ResetRequestsPerAccount, DefaultResetRequestsPerAccount), resetWindow, maxKeys, now),
		resend:       newRateLimiter(1, resendInterval, maxKeys, now),
		userActions:  newRateLimiter(resolveCount(o.UserActionsPerHour, DefaultUserActionsPerHour), userActionWindow, maxKeys, now),
		directory:    newRateLimiter(DirectoryRequestsPerMinute, time.Minute, maxKeys, now),
		hashes:       newHashBound(resolveCount(o.HashPerIP, DefaultHashPerIP), maxKeys),
	}
}

// resolveCount applies the convention of Options: zero selects def, a
// negative value disables (returned as 0, which the limiter reads as "no
// limit").
func resolveCount(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return v
}

// resolveWindow returns def for a window of zero or less.
func resolveWindow(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// rateLimiter allows at most limit events per key within any window of the
// given length (a sliding log: it keeps the time of each counted event, at
// most limit per key).
//
// The state cannot grow without bound, and every operation does a small,
// amortised constant amount of work under the mutex, independent of the
// number of keys:
//   - By default the keys are kept in a list ordered by their last counted
//     event, the least recently counted first, and a key whose events have
//     all left the window is dropped from the front of that list by the
//     next call. When the table holds maxKeys keys and a new key comes, the
//     least recently counted key is evicted and the new key is admitted. The
//     evicted client or address starts again with a fresh budget; to evict
//     a given key, somebody has to bring maxKeys newer keys first, each of
//     which has passed the other limits. A full table never refuses:
//     refusing new keys would let anybody who fills it lock everybody else
//     out.
//   - The table of failed logins per account is built with
//     evictingByFailures: there an evicted key is a fresh set of guesses at
//     that account's password. Two rules hold there.
//     First, only a final failure changes the table. A take holds a pending
//     place (it counts against the key's limit at once, so that attempts in
//     flight cannot pass the limit together) and nothing else; confirm makes
//     it a failure, giveBack drops it. A login that ends without counting —
//     the password was right, the server could not decide, the client went
//     away — leaves the table as if it had never been made: no entry moves,
//     no credit changes, nothing is pushed out.
//     Second, the table makes room by failures, not by age. The list is a
//     clock (GCLOCK) that only looks move: a confirmed failure of a key in
//     the table gives its entry one credit (never more than one per failure
//     after its first that is recorded) and does not move it; a confirmed
//     failure of a new key puts it at the back, after room has been made.
//     To make room the front entry is looked at: if its failures have left
//     the window it goes; if it has credit, it gives up one and moves to the
//     back; otherwise it goes.
//     The price: an entry holding e live failures when it is pushed out had
//     to reach the front e times, and each time maxKeys-1 other entries had
//     to leave the places ahead of it (a walk runs only when the table is
//     full, and the entry is at its back after it came in and after each
//     skip). An entry leaves the place ahead by a look that removes it or
//     skips it to the back, or by time (pruned at the front, or dropped when
//     its key fails again after its failures have left the window). Each
//     such step uses up one confirmed failure of another key: the first
//     failure of the entry that goes, or the failure that gave the credit
//     that is used. So pushing out e failures of one account costs at least
//     e·(maxKeys-1) counted failed logins of other keys — those of other
//     users and of the window before included. The same steps advance every
//     entry behind them, so the bound is per account: an attacker who
//     attacks many accounts at once pays it once for all of them.
//     Expired entries: the front is pruned by time; an entry whose failures
//     have left the window but that stands behind live ones goes when it
//     reaches the front or when its key fails again.
//     Cost: every look removes an entry or uses up a credit, and a confirmed
//     failure gives at most one credit, so the looks are at most two per
//     confirmed failure on average; a single confirm can look at up to
//     (limit-1)·maxKeys+1 entries when it uses up credit that earlier
//     failures paid for.
type rateLimiter struct {
	limit   int // <= 0: no limit, nothing is recorded
	window  time.Duration
	maxKeys int // <= 0: no cap on the number of keys
	now     func() time.Time

	// evictByFailures makes room in a full table by failures instead of
	// age (evictingByFailures); name says which table in the log line.
	evictByFailures bool
	name            string

	mu      sync.Mutex
	entries map[string]*rlEntry
	order   *list.List // of *rlEntry: least recently counted first; for evictByFailures the clock
	// pending holds the entries of a table that evicts by failures that
	// have only events in flight (no place in order), oldest first.
	pending     *list.List
	evicted     int // evictions since the last warning
	lastWarn    time.Time
	inspections int // entries looked at to make room (evictByFailures; for tests)
	pendings    int // pending places taken (evictByFailures; for tests)
}

// evictingByFailures switches l to making room by failures (see
// rateLimiter); name names the table in the log. It returns l.
func (l *rateLimiter) evictingByFailures(name string) *rateLimiter {
	l.evictByFailures = true
	l.name = name
	return l
}

// rlEntry is the state of one key.
type rlEntry struct {
	key string
	// events are the counted events, oldest first; older ones are dropped
	// when the key is touched. Never empty while the entry is in order.
	events []time.Time
	// elem is the entry's place in order; nil for an entry of a table that
	// evicts by failures that holds only pending events.
	elem *list.Element
	// credit is the number of arrivals at the front of the list the entry
	// still survives (evictByFailures only). It is never more than
	// len(events)-1, and only a confirmed failure raises it, by one.
	credit int
	// inflight holds the attempts of the key still in flight (a table that
	// evicts by failures); nil when there are none. It is kept apart so
	// that an entry stays as small as the memory model counts it
	// (RateLimitKeyBytes): attempts in flight are few.
	inflight *rlInflight
}

// rlInflight is the state of the attempts of one key that are in flight.
type rlInflight struct {
	// stamps are their pending events, oldest first: they count against the
	// key's limit, nothing else, until confirm makes them failures or
	// giveBack drops them.
	stamps []time.Time
	// elem is the entry's place in pending while it is not in order.
	elem *list.Element
}

// pend returns the pending events of e.
func (e *rlEntry) pend() []time.Time {
	if e.inflight == nil {
		return nil
	}
	return e.inflight.stamps
}

// setPend replaces the pending events of e; the state goes when nothing is
// left in it.
func (e *rlEntry) setPend(stamps []time.Time) {
	if e.inflight == nil {
		e.inflight = &rlInflight{}
	}
	e.inflight.stamps = stamps
	if len(stamps) == 0 && e.inflight.elem == nil {
		e.inflight = nil
	}
}

// pelem returns the entry's place in pending (nil when it has none).
func (e *rlEntry) pelem() *list.Element {
	if e.inflight == nil {
		return nil
	}
	return e.inflight.elem
}

// setPelem sets the entry's place in pending.
func (e *rlEntry) setPelem(el *list.Element) {
	if e.inflight == nil {
		if el == nil {
			return
		}
		e.inflight = &rlInflight{}
	}
	e.inflight.elem = el
	if el == nil && len(e.inflight.stamps) == 0 {
		e.inflight = nil
	}
}

func newRateLimiter(limit int, window time.Duration, maxKeys int, now func() time.Time) *rateLimiter {
	if now == nil {
		now = time.Now
	}
	return &rateLimiter{
		limit:   limit,
		window:  window,
		maxKeys: maxKeys,
		now:     now,
		entries: map[string]*rlEntry{},
		order:   list.New(),
		pending: list.New(),
	}
}

// take counts one event for key if the key has room for it. It returns the
// time stamp of the recorded event (for giveBack) and ok. When there is no
// room it records nothing and returns how long it will take until there is.
//
// In a table that evicts by failures the event is pending: it counts
// against the key's limit at once (so that attempts in flight cannot pass
// the limit together) and changes nothing else — no entry moves, no credit
// changes, nothing is pushed out — until confirm makes it a failure. An
// attempt that is given back therefore leaves the table as if it had never
// been made.
func (l *rateLimiter) take(key string) (stamp time.Time, retryAfter time.Duration, ok bool) {
	if l.limit <= 0 {
		return time.Time{}, 0, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.evictByFailures {
		return l.takePendingLocked(key, now)
	}
	e, retryAfter, ok := l.roomLocked(key, now)
	if !ok {
		return time.Time{}, retryAfter, false
	}
	if e == nil {
		if l.maxKeys > 0 && len(l.entries) >= l.maxKeys {
			l.evictOldestLocked(now)
		}
		e = &rlEntry{key: key}
		e.elem = l.order.PushBack(e)
		l.entries[key] = e
	} else {
		l.order.MoveToBack(e.elem)
	}
	e.events = append(e.events, now)
	return now, 0, true
}

// confirm makes the pending event stamp of key a counted failure, in a table
// that evicts by failures (in other tables an event counts from take on and
// confirm does nothing). The entry gets one credit; it is not moved. A key
// without a place in the table gets one at the back, and only then is room
// made (makeRoomByFailuresLocked): every change of order and credit comes
// from a confirmed failure. It first drops the key's events and pending
// events that have left the window (trimFailureLocked: what time does
// anyway); without the pending event stamp (given back, or left the
// window) it does nothing more.
func (l *rateLimiter) confirm(key string, stamp time.Time) {
	if l.limit <= 0 || !l.evictByFailures {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.entries[key]
	if e == nil {
		return
	}
	l.trimFailureLocked(e, now)
	if l.entries[key] != e {
		return
	}
	pend := e.pend()
	i := stampIndex(pend, stamp)
	if i < 0 {
		return
	}
	if e.elem == nil {
		l.pruneLocked(now)
		if l.maxKeys > 0 && l.order.Len() >= l.maxKeys {
			l.makeRoomByFailuresLocked(now)
		}
		l.pending.Remove(e.pelem())
		e.setPelem(nil)
		e.elem = l.order.PushBack(e)
	}
	e.setPend(append(pend[:i], pend[i+1:]...))
	e.events = append(e.events, now)
	e.credit = min(e.credit+1, len(e.events)-1)
}

// takePendingLocked is take for a table that evicts by failures. It records
// a pending event and changes nothing else; in particular it neither trims
// nor moves the key's entry, so that an attempt that is given back leaves no
// trace. Only the front of the clock and of pending are pruned, by time
// alone (what is pruned there has left the window whatever happens).
func (l *rateLimiter) takePendingLocked(key string, now time.Time) (stamp time.Time, retryAfter time.Duration, ok bool) {
	l.pruneLocked(now)
	l.prunePendingLocked(now)
	e := l.entries[key]
	if e == nil {
		e = &rlEntry{key: key}
		l.entries[key] = e
		e.setPelem(l.pending.PushBack(e))
	} else if live := l.liveEventsLocked(e, now); len(live) >= l.limit {
		return time.Time{}, live[len(live)-l.limit].Add(l.window).Sub(now), false
	}
	e.setPend(append(e.pend(), now))
	l.pendings++
	return now, 0, true
}

// pendingsTaken returns the number of pending places taken so far (for
// tests: proof that a request got as far as the take).
func (l *rateLimiter) pendingsTaken() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pendings
}

// liveEventsLocked returns the events and pending events of e that are
// still inside the window, in one sorted list, without changing e.
func (l *rateLimiter) liveEventsLocked(e *rlEntry, now time.Time) []time.Time {
	live := func(events []time.Time) []time.Time {
		i := 0
		for i < len(events) && now.Sub(events[i]) >= l.window {
			i++
		}
		return events[i:]
	}
	return mergeEvents(live(e.events), live(e.pend()))
}

// stampIndex returns the index of stamp in events, or -1.
func stampIndex(events []time.Time, stamp time.Time) int {
	for i, t := range events {
		if t.Equal(stamp) {
			return i
		}
	}
	return -1
}

// check reports whether key has room for one more event, like take, but
// counts nothing: a request that is only checked holds no place. When there
// is no room it returns how long it will take until there is.
func (l *rateLimiter) check(key string) (retryAfter time.Duration, ok bool) {
	if l.limit <= 0 {
		return 0, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, retryAfter, ok = l.roomLocked(key, l.now())
	return retryAfter, ok
}

// roomLocked drops what has left the window and reports whether key has
// room for one more event. It returns the key's entry (nil when the key
// has none) and, without room, the time until the oldest event that has to
// go leaves the window.
func (l *rateLimiter) roomLocked(key string, now time.Time) (e *rlEntry, retryAfter time.Duration, ok bool) {
	l.pruneLocked(now)
	e = l.entries[key]
	if e != nil && l.evictByFailures {
		// Look only: a check must change nothing in this table.
		if live := l.liveEventsLocked(e, now); len(live) >= l.limit {
			return e, live[len(live)-l.limit].Add(l.window).Sub(now), false
		}
		return e, 0, true
	}
	if e != nil && !l.trimLocked(e, now) {
		e = nil
	}
	if e != nil && len(e.events) >= l.limit {
		// The event that has to leave the window to make room.
		return e, e.events[len(e.events)-l.limit].Add(l.window).Sub(now), false
	}
	return e, 0, true
}

// mergeEvents returns the events of two sorted lists in one sorted list.
func mergeEvents(a, b []time.Time) []time.Time {
	if len(b) == 0 {
		return a
	}
	out := make([]time.Time, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i].Before(b[j]) {
			out = append(out, a[i])
			i++
		} else {
			out = append(out, b[j])
			j++
		}
	}
	out = append(out, a[i:]...)
	return append(out, b[j:]...)
}

// giveBack removes an event that take recorded for key, for an attempt that
// turned out not to count (a successful login, a request the server could
// not handle). Without such an event it does nothing. In a table that evicts
// by failures it drops the pending event and changes nothing else; a
// confirmed failure is not given back.
func (l *rateLimiter) giveBack(key string, stamp time.Time) {
	if l.limit <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		return
	}
	if l.evictByFailures {
		pend := e.pend()
		if i := stampIndex(pend, stamp); i >= 0 {
			if e.elem == nil && len(pend) == 1 {
				l.removeLocked(e)
				return
			}
			e.setPend(append(pend[:i], pend[i+1:]...))
		}
		return
	}
	if i := stampIndex(e.events, stamp); i >= 0 {
		e.events = append(e.events[:i], e.events[i+1:]...)
	}
	if len(e.events) == 0 {
		l.removeLocked(e)
	}
}

// pruneLocked drops keys from the front of the order whose last event has
// left the window. It stops at the first key that is still in use, so its
// cost is paid once per key that was ever added. (In a table that evicts by
// failures the order is the clock, so an expired key that stands behind a
// live one stays until it reaches the front.)
func (l *rateLimiter) pruneLocked(now time.Time) {
	for front := l.order.Front(); front != nil; front = l.order.Front() {
		e := front.Value.(*rlEntry)
		if now.Sub(e.events[len(e.events)-1]) < l.window {
			return
		}
		l.dropFromOrderLocked(e)
	}
}

// prunePendingLocked drops, from the front of pending, the entries whose
// pending events have all left the window (attempts that never ended, for
// example after a panic). It stops at the first entry still in use.
func (l *rateLimiter) prunePendingLocked(now time.Time) {
	for front := l.pending.Front(); front != nil; front = l.pending.Front() {
		e := front.Value.(*rlEntry)
		if pend := e.pend(); len(pend) > 0 && now.Sub(pend[len(pend)-1]) < l.window {
			return
		}
		l.removeLocked(e)
	}
}

// trimFailureLocked drops the events and pending events of e that left the
// window, in a table that evicts by failures (only confirm calls it), and
// keeps the credit within the failures left. An entry without failures
// leaves the order; without pending events either, it is removed.
func (l *rateLimiter) trimFailureLocked(e *rlEntry, now time.Time) {
	i := 0
	for i < len(e.events) && now.Sub(e.events[i]) >= l.window {
		i++
	}
	if i > 0 {
		e.events = append(e.events[:0], e.events[i:]...)
	}
	pend := e.pend()
	j := 0
	for j < len(pend) && now.Sub(pend[j]) >= l.window {
		j++
	}
	if j > 0 {
		e.setPend(append(pend[:0], pend[j:]...))
	}
	switch {
	case len(e.events) > 0:
		e.credit = min(e.credit, len(e.events)-1)
	case e.elem != nil:
		l.dropFromOrderLocked(e)
	case len(e.pend()) == 0:
		l.removeLocked(e)
	}
}

// dropFromOrderLocked takes e out of order: it is removed, unless it has
// pending events (a table that evicts by failures), which then keep it in
// pending without failures or credit.
func (l *rateLimiter) dropFromOrderLocked(e *rlEntry) {
	if len(e.pend()) == 0 {
		l.removeLocked(e)
		return
	}
	l.order.Remove(e.elem)
	e.elem = nil
	e.events = nil
	e.credit = 0
	e.setPelem(l.pending.PushBack(e))
}

// trimLocked drops the events of e that left the window. It removes e and
// returns false when none is left.
func (l *rateLimiter) trimLocked(e *rlEntry, now time.Time) bool {
	i := 0
	for i < len(e.events) && now.Sub(e.events[i]) >= l.window {
		i++
	}
	if i == len(e.events) {
		l.removeLocked(e)
		return false
	}
	if i > 0 {
		e.events = append(e.events[:0], e.events[i:]...)
	}
	return true
}

// evictOldestLocked removes the least recently counted key to make room,
// and logs at most one warning per minute about it.
func (l *rateLimiter) evictOldestLocked(now time.Time) {
	front := l.order.Front()
	if front == nil {
		return
	}
	l.removeLocked(front.Value.(*rlEntry))
	l.evicted++
	if now.Sub(l.lastWarn) >= time.Minute {
		log.Printf("frontend: rate limiter full (%d keys): evicted %d least recently used entries", l.maxKeys, l.evicted)
		l.lastWarn = now
		l.evicted = 0
	}
}

// makeRoomByFailuresLocked removes one key from a full table that evicts by
// failures (see rateLimiter): the front entry goes if its events have left
// the window or it has no credit left; otherwise it gives up one credit and
// moves to the back, and the next front entry is looked at. Each look
// removes an entry or uses up a credit that an earlier confirmed failure
// gave, so the work is constant on average and does not grow with the
// table. A live entry that goes is logged (at most once a minute,
// warnEvictedLiveLocked).
func (l *rateLimiter) makeRoomByFailuresLocked(now time.Time) {
	for front := l.order.Front(); front != nil; front = l.order.Front() {
		l.inspections++
		e := front.Value.(*rlEntry)
		switch {
		case now.Sub(e.events[len(e.events)-1]) >= l.window:
			l.dropFromOrderLocked(e)
		case e.credit > 0:
			e.credit--
			l.order.MoveToBack(front)
			continue
		default:
			l.dropFromOrderLocked(e)
			l.warnEvictedLiveLocked(now)
		}
		return
	}
}

// warnEvictedLiveLocked counts an entry with failures still in their window
// that a full table pushed out, and logs at most one warning per minute
// about it, naming the setting that sizes the table (no address).
func (l *rateLimiter) warnEvictedLiveLocked(now time.Time) {
	l.evicted++
	if now.Sub(l.lastWarn) >= time.Minute {
		log.Printf("frontend: rate limiter %s full (%d keys): pushed out %d entries with failures still in their window "+
			"since the last warning; the table is too small for the current traffic, raise frontend.rate_limit_max_keys",
			l.name, l.maxKeys, l.evicted)
		l.lastWarn = now
		l.evicted = 0
	}
}

func (l *rateLimiter) removeLocked(e *rlEntry) {
	if e.elem != nil {
		l.order.Remove(e.elem)
		e.elem = nil
	}
	if el := e.pelem(); el != nil {
		l.pending.Remove(el)
	}
	e.inflight = nil
	delete(l.entries, e.key)
}

// count returns the number of events recorded for key, pending ones
// included (for tests).
func (l *rateLimiter) count(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.entries[key]; e != nil {
		return len(e.events) + len(e.pend())
	}
	return 0
}

// size returns the number of keys the limiter holds state for.
func (l *rateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// clientIP returns the address of the client: the peer of the connection
// (r.RemoteAddr). Headers such as X-Forwarded-For or X-Real-IP are ignored:
// tunneld terminates TLS itself, so no proxy in front of it could vouch for
// them, and a client could name any address. An IPv4 peer on a dual-stack
// listener is returned as IPv4. The zero Addr means RemoteAddr held no
// address.
func clientIP(r *http.Request) netip.Addr {
	return peerAddr(r.RemoteAddr)
}

// sourceKey is the rate-limit key of a client address. An IPv4 address
// stands for itself. An IPv6 address stands for its /64, because a single
// host usually gets a whole /64 and can pick any address in it. Requests
// without a usable address share one key.
func sourceKey(addr netip.Addr) string {
	if !addr.IsValid() {
		return "unknown"
	}
	if addr.Is4() {
		return addr.String()
	}
	p, err := addr.WithZone("").Prefix(64)
	if err != nil {
		return "unknown"
	}
	return p.String()
}

// keyOf returns the rate-limit key of an email address (accountKey, or the
// replacement a test set).
func (o Options) keyOf(email string) string {
	if o.accountKeyOf != nil {
		return o.accountKeyOf(email)
	}
	return accountKey(email)
}

// accountKey is the rate-limit key of an email address as typed: trimmed
// and lower-cased, so that changing the case does not open a new budget.
// The address is hashed so that the limiter neither keeps addresses in
// memory nor grows with the length of what a client sends.
func accountKey(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return string(sum[:])
}
