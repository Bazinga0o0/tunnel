package main

import (
	"fmt"
	"log/slog"
	"math"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeudp"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend"
)

// The memory budget of the server process.
//
// Each limit on the tunnel path bounds a number of things that hold memory:
// visitor connections with their tunnel streams, tunnel sessions and the
// ports they hold, connections on the public HTTPS listener and on the
// tunnel listener before the login, UDP flows. What one such thing is
// counted at is a constant next to the default it justifies
// (edgetcp.ConnMemoryBytes, acceptor.SessionMemoryBytes,
// edgetcp.ListenerMemoryBytes, edgeudp.ListenerMemoryBytes,
// config.TLSHandshakeMemoryBytes, config.HTTPServer.ConnMemoryBytes,
// edgeudp.FlowMemoryBytes): what memory_measure_test.go measured for the
// worst case it could produce, rounded up, not a bound the code enforces.
// The doc of each constant names what it covers and what is left out.
// worstCaseMemory adds them up for a configuration, together with the UDP
// queue budget, the password hashing, the web UI's rate-limit tables
// (frontend.RateLimitBytesPerKey) and an allowance for the rest of the
// process. With the defaults the sum stays below defaultsBudget
// (TestDefaultLimitsFitTheMemoryBudget).
//
// A tunnel stream that an edge is done with and the tunnel client keeps open
// stays in the sum: it keeps its slot of edge.max_conns or
// edge.udp.max_flows until it is gone from the session, and costs no more
// than a visitor connection or flow while it waits (edgeguard.RetirePaced
// for HTTP and TCP, edgeguard.Retire for UDP).
//
// Not in the sum, because nothing here can measure or bound them: the
// kernel's socket buffers (cgroup v2 charges them to the unit as well).

const (
	// unitMemoryMax is MemoryMax= of systemd/tunneld.service (2G).
	unitMemoryMax = 2 << 30
	// defaultsBudget is the part of unitMemoryMax that the worst case of the
	// default limits may take: 75 %. The rest is headroom for the garbage
	// collector below GOMEMLIMIT and for memory outside the Go heap, such as
	// kernel socket buffers.
	defaultsBudget = unitMemoryMax / 4 * 3

	// passwordHashMemoryBytes is the memory of one argon2id hash as the
	// server makes them (m=65536 KiB); limits.hash_concurrency of them run
	// at a time. A stored hash with a larger m (the parser accepts up to
	// 256 MiB) costs more to verify.
	passwordHashMemoryBytes = 64 << 20

	// otherMemoryBytes is the allowance for the rest of the process: the Go
	// runtime and its metadata, the code's own tables (registry, limiters,
	// metrics), the database pool, the mail queue and the web UI's requests.
	// The web UI's rate-limit tables have a term of their own.
	otherMemoryBytes = 192 << 20
)

// memoryPart is one term of the worst case: count things of unit bytes each,
// bounded by key.
type memoryPart struct {
	key       string
	what      string
	count     int64
	unit      int64
	unbounded bool // the limit is disabled, or so large that the term overflows: no bound
	tooLarge  bool // unbounded because the configured value is too large to count
	// tooLargeWhat names what is too large when it is not the key itself:
	// the unit of the term came from other settings.
	tooLargeWhat string
}

// state names why an unbounded term has no bound.
// A term can have two reasons at once: its own limit disabled and a unit
// that is too large to count (tooLargeWhat); both are named.
func (p memoryPart) state() string {
	switch {
	case p.tooLargeWhat != "" && !p.tooLarge:
		return "disabled; " + p.tooLargeWhat + " too large to count"
	case p.tooLargeWhat != "":
		return p.tooLargeWhat + " too large to count"
	case p.tooLarge:
		return "too large to count"
	}
	return "disabled"
}

// why names, for the warning, what leaves an unbounded term without a bound.
func (p memoryPart) why() string {
	switch {
	case p.tooLargeWhat != "" && !p.tooLarge:
		return p.key + " disabled, " + p.tooLargeWhat + " too large to count"
	case p.tooLargeWhat != "":
		return p.tooLargeWhat + " too large to count"
	}
	return p.key + " " + p.state()
}

func (p memoryPart) bytes() int64 { return p.count * p.unit }

// memoryEstimate is the worst case of a configuration's limits.
type memoryEstimate struct {
	parts []memoryPart
}

// total returns the sum of the bounded terms; it stops at math.MaxInt64
// instead of wrapping.
func (e memoryEstimate) total() int64 {
	var n int64
	for _, p := range e.parts {
		if p.unbounded {
			continue
		}
		if b := p.bytes(); n > math.MaxInt64-b {
			return math.MaxInt64
		} else {
			n += b
		}
	}
	return n
}

// unbounded returns the keys whose term has no bound: the limit is disabled
// or too large to count.
func (e memoryEstimate) unbounded() []string {
	var keys []string
	for _, p := range e.parts {
		if p.unbounded {
			keys = append(keys, p.key)
		}
	}
	return keys
}

func (e memoryEstimate) String() string {
	var b strings.Builder
	for _, p := range e.parts {
		switch {
		case p.unbounded:
			fmt.Fprintf(&b, "%-34s %-40s no bound (%s)\n", p.key, p.what, p.state())
		case p.unit == 1: // a byte budget
			fmt.Fprintf(&b, "%-34s %-40s %21s %9s\n", p.key, p.what, "", size(p.bytes()))
		default:
			fmt.Fprintf(&b, "%-34s %-40s %7d x %9s = %9s\n", p.key, p.what, p.count, size(p.unit), size(p.bytes()))
		}
	}
	fmt.Fprintf(&b, "%-34s %-40s %31s\n", "total", "", size(e.total()))
	return b.String()
}

// size renders a number of bytes in KiB, MiB or GiB.
func size(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n%1024 != 0:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	default:
		return fmt.Sprintf("%d KiB", n>>10)
	}
}

// limitCount resolves a count limit of the config: zero selects def, a
// negative value disables it (ok false).
func limitCount(v, def int) (n int64, ok bool) {
	switch {
	case v == 0:
		return int64(def), true
	case v < 0:
		return 0, false
	}
	return int64(v), true
}

// worstCaseMemory returns the most memory the server can come to hold within
// the configured limits.
func worstCaseMemory(cfg *config.Config) memoryEstimate {
	var e memoryEstimate
	// addCount adds a term of n things (ok false: the limit is disabled). A
	// count so large that the product overflows, or a unit that saturated
	// itself (frontend.RateLimitBytesPerKey), has no bound either: the value
	// the operator set is too large to count.
	addCount := func(key, what string, n int64, ok bool, unit int64) {
		tooLarge := false
		if ok && (unit < 0 || unit == math.MaxInt64 && n > 0 || unit > 0 && n > math.MaxInt64/unit) {
			n, ok, tooLarge = 0, false, true
		}
		e.parts = append(e.parts, memoryPart{key: key, what: what, count: n, unit: unit, unbounded: !ok, tooLarge: tooLarge})
	}
	add := func(key, what string, v, def int, unit int64) {
		n, ok := limitCount(v, def)
		addCount(key, what, n, ok, unit)
	}

	add("edge.max_conns", "visitor connections with their streams", cfg.Edge.MaxConns, edgetcp.DefaultMaxConns, edgetcp.ConnMemoryBytes)

	add("http_server.max_conns", "public HTTPS connections", cfg.HTTPServer.MaxConns, config.DefaultMaxConns, cfg.HTTPServer.ConnMemoryBytes())

	sessions, sessionsBounded := limitCount(cfg.Tunnel.MaxSessions, acceptor.DefaultMaxSessions)
	addCount("tunnel.max_sessions", "tunnel sessions", sessions, sessionsBounded, acceptor.SessionMemoryBytes)
	// Every session may hold one port of each kind; the port range bounds
	// them as well.
	ports := func(r config.PortRange) (int64, bool) {
		inRange := int64(r.High - r.Low + 1)
		if !sessionsBounded {
			return inRange, true
		}
		return min(sessions, inRange), true
	}
	if cfg.TCP.Enabled {
		n, ok := ports(cfg.TCP.PortRange)
		addCount("tunnel.max_sessions", "TCP ports of the sessions (one each)", n, ok, edgetcp.ListenerMemoryBytes)
	}
	if cfg.UDP.Enabled {
		n, ok := ports(cfg.UDP.PortRange)
		addCount("tunnel.max_sessions", "UDP ports of the sessions (one each)", n, ok, edgeudp.ListenerMemoryBytes)
	}
	add("tunnel.max_unauth_conns", "tunnel connections before login", cfg.Tunnel.MaxUnauthConns, acceptor.DefaultMaxUnauthConns, config.TLSHandshakeMemoryBytes)

	if cfg.UDP.Enabled {
		u := cfg.Edge.UDP
		add("edge.udp.max_flows", "UDP flows", u.MaxFlows, edgeudp.DefaultMaxFlows, edgeudp.FlowMemoryBytes)
		add("edge.udp.max_queued_bytes", "datagrams queued for the tunnels", u.MaxQueuedBytes, edgeudp.DefaultMaxQueuedBytes, 1)
	}
	if cfg.Database.URL != "" {
		add("limits.hash_concurrency", "password hashes at a time", cfg.Limits.HashConcurrency, auth.DefaultHashConcurrency, passwordHashMemoryBytes)
		// Every table full, every key's log filled to its table's limit.
		perKey := frontend.RateLimitBytesPerKey(frontendOptions(cfg))
		add("frontend.rate_limit_max_keys", "keys of the web UI's rate-limit tables", cfg.Frontend.RateLimitMaxKeys,
			frontend.DefaultRateLimitMaxKeys, perKey)
		if perKey == math.MaxInt64 {
			// The cost of one key saturated: a table limit is too large, not
			// the number of keys.
			e.parts[len(e.parts)-1].tooLargeWhat = "a rate limit of the web UI (frontend.*_per_*)"
		}
	}
	e.parts = append(e.parts, memoryPart{key: "(allowance)", what: "the rest of the process", count: 1, unit: otherMemoryBytes})
	return e
}

// memoryWarning returns the start-up warning for a configuration whose limits
// let the server hold more memory than the Go memory limit in force
// (GOMEMLIMIT, see runtime/debug.SetMemoryLimit), and "" when they do not or
// no limit is set. The garbage collector cannot keep the process below that
// limit once that much is in use: it runs nearly all the time, and in the
// unit the kernel ends the process at MemoryMax.
func memoryWarning(e memoryEstimate, limit int64) string {
	if limit <= 0 || limit == math.MaxInt64 {
		return ""
	}
	var unbounded []string
	for _, p := range e.parts {
		if p.unbounded {
			unbounded = append(unbounded, p.why())
		}
	}
	if len(unbounded) == 0 && e.total() <= limit {
		return ""
	}
	// The largest terms first: lowering those helps most.
	parts := append([]memoryPart(nil), e.parts...)
	sort.SliceStable(parts, func(i, j int) bool { return parts[i].bytes() > parts[j].bytes() })
	var lower []string
	for _, p := range parts {
		switch {
		case p.unbounded || strings.HasPrefix(p.key, "("):
		case p.unit == 1:
			lower = append(lower, fmt.Sprintf("%s (%s)", p.key, size(p.bytes())))
		default:
			lower = append(lower, fmt.Sprintf("%s (%d x %s = %s)", p.key, p.count, size(p.unit), size(p.bytes())))
		}
	}
	head := fmt.Sprintf("the configured limits allow the server to hold up to %s, more than the Go memory limit of %s (GOMEMLIMIT)",
		size(e.total()), size(limit))
	if len(unbounded) > 0 {
		head = fmt.Sprintf("the configured limits put no bound on the server's memory (%s), and the Go memory limit is %s (GOMEMLIMIT)",
			strings.Join(unbounded, ", "), size(limit))
	}
	return head + "; under load the process can then run out of memory. Lower " + strings.Join(lower, ", ") +
		", or raise GOMEMLIMIT together with MemoryMax of the systemd unit"
}

// warnAboutMemory logs memoryWarning for the Go memory limit in force.
func warnAboutMemory(cfg *config.Config, logger *slog.Logger) {
	if w := memoryWarning(worstCaseMemory(cfg), debug.SetMemoryLimit(-1)); w != "" {
		logger.Warn(w)
	}
}
