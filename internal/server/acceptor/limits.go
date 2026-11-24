package acceptor

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// Defaults of the limits in Options.
const (
	DefaultHandshakeTimeout     = 10 * time.Second
	DefaultVerifyTimeout        = 5 * time.Second
	DefaultMaxUnauthConns       = 256
	DefaultMaxUnauthConnsPerIP  = 16
	DefaultMaxPreAuthFrameSize  = 4 << 10
	DefaultMaxControlFrameSize  = 16 << 10
	DefaultMaxStreamsPerSession = 512
	// DefaultMaxStreamsPerUser bounds the streams of all sessions of one
	// user together, so that the memory one account can make the server
	// hold for its streams does not grow with the number of its sessions.
	DefaultMaxStreamsPerUser      = 256
	DefaultControlBurst           = 20
	DefaultControlRefillPerSecond = 5
	// The session limits are the registry's, which enforces them. At
	// SessionMemoryBytes per session, plus a TCP and a UDP port each,
	// DefaultMaxSessions bounds the sessions to about 66 MiB (see
	// cmd/tunneld/memory.go for the whole budget).
	DefaultMaxSessionsPerUser = registry.DefaultMaxSessionsPerUser
	DefaultMaxSessions        = registry.DefaultMaxSessions
)

// SessionMemoryBytes is the memory counted for one tunnel session without a
// port of its own and without streams: the TLS connection, the yamux session
// with its control stream, and six goroutines. Measured
// (cmd/tunneld/memory_measure_test.go, go1.27.4): 69 KiB for an idle
// authenticated session, 55-58 KiB for one with an HTTP name or a TCP port
// (within the noise). On top of that come the ping answers that the ping
// allowance lets wait at a time when the client stops reading:
// protocol.MaxParkedPingAnswers (two) of protocol.PingAnswerMemoryBytes
// (10 KiB) each. 89 KiB, rounded up to 96 KiB. A UDP or TCP port of the session
// is counted on its own (edgeudp.ListenerMemoryBytes,
// edgetcp.ListenerMemoryBytes), and so is every stream
// (edgetcp.ConnMemoryBytes, edgeudp.FlowMemoryBytes). Connections still in
// the handshake are counted at config.TLSHandshakeMemoryBytes. Frames that
// pile up in the control stream while the session is busy with one message
// can take up to two stream windows for a moment; the stream gives that
// memory back once it is read.
const SessionMemoryBytes = 96 << 10

// maxFrameSize is the ceiling for any control frame. It is what remains when
// a frame size limit is disabled, and no configured size can exceed it.
const maxFrameSize = 1 << 20

// limits are the Options limits after resolving defaults. Unless noted, 0
// means "no limit".
type limits struct {
	handshakeTimeout    time.Duration
	verifyTimeout       time.Duration
	maxUnauthConns      int
	maxUnauthConnsPerIP int
	preAuthFrameSize    uint32 // never 0
	controlFrameSize    uint32 // never 0
	acceptBacklog       int    // passed to protocol.ServerOptions; negative disables there
	maxStreams          int
	maxStreamsPerUser   int
	controlBurst        int // the throttle is off when burst or refill is 0
	controlRefill       int
	maxSessionsPerUser  int
	maxSessions         int
}

func resolveLimits(o Options) limits {
	return limits{
		handshakeTimeout:    pickDuration(o.HandshakeTimeout, DefaultHandshakeTimeout),
		verifyTimeout:       pickDuration(o.VerifyTimeout, DefaultVerifyTimeout),
		maxUnauthConns:      pick(o.MaxUnauthConns, DefaultMaxUnauthConns),
		maxUnauthConnsPerIP: pick(o.MaxUnauthConnsPerIP, DefaultMaxUnauthConnsPerIP),
		preAuthFrameSize:    pickFrameSize(o.MaxPreAuthFrameSize, DefaultMaxPreAuthFrameSize),
		controlFrameSize:    pickFrameSize(o.MaxControlFrameSize, DefaultMaxControlFrameSize),
		acceptBacklog:       pickBacklog(o.AcceptBacklog),
		maxStreams:          pick(o.MaxStreamsPerSession, DefaultMaxStreamsPerSession),
		maxStreamsPerUser:   pick(o.MaxStreamsPerUser, DefaultMaxStreamsPerUser),
		controlBurst:        pick(o.ControlBurst, DefaultControlBurst),
		controlRefill:       pick(o.ControlRefillPerSecond, DefaultControlRefillPerSecond),
		maxSessionsPerUser:  pick(o.MaxSessionsPerUser, DefaultMaxSessionsPerUser),
		maxSessions:         pick(o.MaxSessions, DefaultMaxSessions),
	}
}

// pick resolves one option: zero selects def, a negative value disables the
// limit (0).
func pick(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return v
}

func pickDuration(v, def time.Duration) time.Duration {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return v
}

// pickFrameSize resolves a frame size: zero selects def, a negative value
// disables the limit, which leaves maxFrameSize.
func pickFrameSize(v, def int) uint32 {
	switch {
	case v == 0:
		return uint32(def)
	case v < 0, v > maxFrameSize:
		return maxFrameSize
	}
	return uint32(v)
}

// pickBacklog resolves the accept backlog. A negative value is passed on:
// protocol.ServerOptions gives it the same meaning.
func pickBacklog(v int) int {
	if v == 0 {
		return protocol.DefaultServerAcceptBacklog
	}
	return v
}

// sessionLimits returns the session limits in the form the registry takes.
// Here 0 means "disabled"; for registry.SessionLimits 0 selects the
// registry's own default and a negative value disables.
func (l limits) sessionLimits() registry.SessionLimits {
	disabledAsNegative := func(v int) int {
		if v == 0 {
			return -1
		}
		return v
	}
	return registry.SessionLimits{
		PerUser: disabledAsNegative(l.maxSessionsPerUser),
		Total:   disabledAsNegative(l.maxSessions),
	}
}

// connLimiter counts the connections that have not authenticated yet, in
// total and per source address.
type connLimiter struct {
	maxTotal int // 0: no limit
	maxPerIP int // 0: no limit

	mu    sync.Mutex
	total int
	perIP map[netip.Addr]int // entries are removed when they reach 0
}

func newConnLimiter(maxTotal, maxPerIP int) *connLimiter {
	return &connLimiter{maxTotal: maxTotal, maxPerIP: maxPerIP, perIP: map[netip.Addr]int{}}
}

// acquire takes a slot for a connection from addr. It returns ok == false
// when a limit is reached. release gives the slot back; calling it more than
// once is harmless.
func (l *connLimiter) acquire(addr net.Addr) (release func(), ok bool) {
	key := sourceKey(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.maxTotal > 0 && l.total >= l.maxTotal {
		return nil, false
	}
	if l.maxPerIP > 0 && l.perIP[key] >= l.maxPerIP {
		return nil, false
	}
	l.total++
	l.perIP[key]++
	var once sync.Once
	return func() { once.Do(func() { l.release(key) }) }, true
}

func (l *connLimiter) release(key netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.perIP[key]--; l.perIP[key] <= 0 {
		delete(l.perIP, key)
	}
}

// sourceKey maps a remote address to the unit the per-source limit counts:
// the IPv4 address, or the /64 of an IPv6 address (a host chooses the lower
// 64 bits freely, so single IPv6 addresses would not limit anything).
// IPv4-mapped IPv6 addresses count as IPv4. Addresses that are not IP
// addresses all share the zero key.
func sourceKey(addr net.Addr) netip.Addr {
	var ip netip.Addr
	switch a := addr.(type) {
	case nil:
	case *net.TCPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
	default:
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			ip = ap.Addr()
		}
	}
	if !ip.IsValid() {
		return netip.Addr{}
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return ip
}

// tokenBucket throttles the control messages of one session. It is used by
// one goroutine only. A nil bucket allows everything.
//
// It counts in billionths of a token, so that refilling is exact integer
// arithmetic: one nanosecond adds refill billionths.
type tokenBucket struct {
	capacity int64
	refill   int64 // tokens per second
	credit   int64
	last     time.Time
}

// tokenCost is the price of one message in billionths of a token.
const tokenCost = int64(time.Second)

// newTokenBucket returns a full bucket of burst tokens that regains
// refillPerSecond tokens per second, or nil (no throttling) when either
// value is zero or less.
func newTokenBucket(burst, refillPerSecond int, now time.Time) *tokenBucket {
	if burst <= 0 || refillPerSecond <= 0 {
		return nil
	}
	capacity := int64(burst) * tokenCost
	return &tokenBucket{capacity: capacity, refill: int64(refillPerSecond), credit: capacity, last: now}
}

// allow takes one token and reports whether there was one.
func (b *tokenBucket) allow(now time.Time) bool {
	if b == nil {
		return true
	}
	// A clock that stepped back gives nothing and takes nothing.
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.last = now
		// After timeToFill the bucket is full whatever it held; checking
		// this first keeps the multiplication below from overflowing.
		if timeToFill := time.Duration(b.capacity / b.refill); elapsed >= timeToFill {
			b.credit = b.capacity
		} else if b.credit += int64(elapsed) * b.refill; b.credit > b.capacity {
			b.credit = b.capacity
		}
	}
	if b.credit < tokenCost {
		return false
	}
	b.credit -= tokenCost
	return true
}

// Accept loop backoff: 5 ms, doubling up to 1 s.
const (
	minAcceptDelay = 5 * time.Millisecond
	maxAcceptDelay = time.Second
)

// nextAcceptDelay returns the pause after one more failed Accept, given the
// previous pause (0 after a success).
func nextAcceptDelay(prev time.Duration) time.Duration {
	if prev <= 0 {
		return minAcceptDelay
	}
	if next := prev * 2; next < maxAcceptDelay {
		return next
	}
	return maxAcceptDelay
}

// clip cuts s to at most n characters. Text from a client goes through it
// before it reaches a log line.
func clip(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// eventLog decides when a frequent event gets a log line: at most one per
// interval, which then carries the number of events since the previous line.
type eventLog struct {
	interval time.Duration

	mu      sync.Mutex
	last    time.Time
	pending int
}

// note records one event. It reports whether to log now and, if so, how many
// events the line stands for.
func (e *eventLog) note(now time.Time) (logNow bool, events int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pending++
	if !e.last.IsZero() && now.Sub(e.last) < e.interval {
		return false, 0
	}
	events, e.pending, e.last = e.pending, 0, now
	return true, events
}
