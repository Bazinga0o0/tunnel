package main

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/edgehttp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeudp"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

// defaultsConfig is database mode with TCP and UDP on and every limit at its
// default: every term of the worst case is present.
const defaultsConfig = `domain: tunnel.test
listen: {tunnel_addr: ":7443", http_addr: ":443"}
tls: {self_signed_hosts: [tunnel.test]}
auth: {csrf_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
database: {url: "postgres://tunneld:secret@127.0.0.1:5432/tunneld?sslmode=disable"}
tcp: {enabled: true}
udp: {enabled: true}
`

// The worst case of the default limits, the measured costs times the
// defaults plus the UDP queue budget, the password hashing and the allowance
// for the rest of the process, stays below 75 % of the unit's MemoryMax.
// Raising a default past the budget turns this test red.
func TestDefaultLimitsFitTheMemoryBudget(t *testing.T) {
	e := worstCaseMemory(loadConfig(t, defaultsConfig))
	t.Log("\n" + e.String())
	require.Empty(t, e.unbounded())
	for _, key := range []string{"edge.max_conns", "http_server.max_conns", "tunnel.max_sessions", "tunnel.max_unauth_conns",
		"edge.udp.max_flows", "edge.udp.max_queued_bytes", "limits.hash_concurrency", "frontend.rate_limit_max_keys", "(allowance)"} {
		assert.Contains(t, partKeys(e), key)
	}
	assert.LessOrEqual(t, e.total(), int64(defaultsBudget),
		"the worst case of the defaults (%s) exceeds 75 %% of MemoryMax (%s)", size(e.total()), size(defaultsBudget))
}

// No single tunnel, user or UDP port may take more than a third of the total
// it draws from, and no single address more than an eighth of the public
// listener, so that a change of a total or of a share is a decision and not
// an accident: with shares close to their totals two tunnels, two accounts,
// one UDP port (with forged sender addresses) or a handful of addresses
// starve everybody else.
func TestDefaultSharesLeaveRoomForOthers(t *testing.T) {
	cases := []struct {
		share, total        string
		shareValue, totalOf int
		parts               int
	}{
		{"edge.http.max_conns_per_tunnel", "edge.max_conns", edgehttp.DefaultMaxConnsPerTunnel, edgetcp.DefaultMaxConns, 3},
		{"edge.tcp.max_conns_per_tunnel", "edge.max_conns", edgetcp.DefaultMaxConnsPerTunnel, edgetcp.DefaultMaxConns, 3},
		{"tunnel.max_streams_per_user", "edge.max_conns", acceptor.DefaultMaxStreamsPerUser, edgetcp.DefaultMaxConns, 3},
		{"edge.udp.max_flows_per_port", "edge.udp.max_flows", edgeudp.DefaultMaxFlowsPerPort, edgeudp.DefaultMaxFlows, 3},
		{"http_server.max_conns_per_ip", "http_server.max_conns", config.DefaultMaxConnsPerIP, config.DefaultMaxConns, 8},
	}
	for _, c := range cases {
		assert.LessOrEqual(t, c.shareValue*c.parts, c.totalOf,
			"%s (%d) is more than 1/%d of %s (%d)", c.share, c.shareValue, c.parts, c.total, c.totalOf)
	}
	assert.Equal(t, edgetcp.DefaultMaxConns, edgehttp.DefaultMaxConns, "the HTTP and TCP edges share one total")

	// The defaults as the server resolves them from an empty configuration.
	cfg := loadConfig(t, defaultsConfig)
	assert.Equal(t, 128, cfg.HTTPServer.Resolved().MaxConnsPerIP)
}

func partKeys(e memoryEstimate) []string {
	var keys []string
	for _, p := range e.parts {
		keys = append(keys, p.key)
	}
	return keys
}

// The configured values replace the defaults in the sum; a disabled limit
// leaves its term without a bound.
func TestWorstCaseMemoryFollowsTheConfiguration(t *testing.T) {
	cfg := loadConfig(t, defaultsConfig)
	cfg.Edge.MaxConns = 10
	cfg.HTTPServer.MaxConns = 20
	cfg.HTTPServer.MaxHeaderBytes = 8192
	cfg.Tunnel.MaxSessions = 30
	cfg.Tunnel.MaxUnauthConns = 40
	cfg.Edge.UDP.MaxFlows = 50
	cfg.Edge.UDP.MaxQueuedBytes = 1 << 20
	cfg.Limits.HashConcurrency = 2
	cfg.Frontend.RateLimitMaxKeys = 60
	cfg.TCP.PortRange = config.PortRange{Low: 10001, High: 10020} // 20 ports, fewer than the sessions
	e := worstCaseMemory(cfg)
	want := map[string]int64{
		"edge.max_conns|visitor connections with their streams": 10 * (704 << 10),
		// The handshake floor: a small head limit does not make a connection
		// cheaper than a stalled TLS handshake.
		"http_server.max_conns|public HTTPS connections":                      20 * (128 << 10),
		"tunnel.max_sessions|tunnel sessions":                                 30 * (96 << 10),
		"tunnel.max_sessions|TCP ports of the sessions (one each)":            20 * (16 << 10),
		"tunnel.max_sessions|UDP ports of the sessions (one each)":            30 * (80 << 10),
		"tunnel.max_unauth_conns|tunnel connections before login":             40 * (128 << 10),
		"edge.udp.max_flows|UDP flows":                                        50 * (96 << 10),
		"edge.udp.max_queued_bytes|datagrams queued for the tunnels":          1 << 20,
		"limits.hash_concurrency|password hashes at a time":                   2 * (64 << 20),
		"frontend.rate_limit_max_keys|keys of the web UI's rate-limit tables": 60 * frontend.RateLimitBytesPerKey(frontend.Options{}),
		"(allowance)|the rest of the process":                                 192 << 20,
	}
	var sum int64
	for _, p := range e.parts {
		k := p.key + "|" + p.what
		w, ok := want[k]
		assert.True(t, ok, "unexpected term %s", k)
		assert.Equal(t, w, p.bytes(), k)
		sum += w
	}
	assert.Len(t, e.parts, len(want))
	assert.Equal(t, sum, e.total())

	// The head limit raises the cost above the floor.
	cfg.HTTPServer.MaxHeaderBytes = 256 << 10
	for _, p := range worstCaseMemory(cfg).parts {
		if p.key == "http_server.max_conns" {
			assert.Equal(t, int64(20*((40<<10)+(256<<10)*3/2)), p.bytes())
		}
	}

	// Without UDP and without a database those terms are gone.
	cfg.UDP.Enabled = false
	cfg.Database.URL = ""
	assert.NotContains(t, partKeys(worstCaseMemory(cfg)), "edge.udp.max_flows")
	assert.NotContains(t, partKeys(worstCaseMemory(cfg)), "limits.hash_concurrency")
	assert.NotContains(t, partKeys(worstCaseMemory(cfg)), "frontend.rate_limit_max_keys")

	cfg.Edge.MaxConns = -1
	cfg.HTTPServer.MaxConns = -1
	assert.Equal(t, []string{"edge.max_conns", "http_server.max_conns"}, worstCaseMemory(cfg).unbounded())

	// Without a session limit the ports of the sessions are still bounded
	// by the port range.
	cfg.TCP.Enabled = true
	cfg.Tunnel.MaxSessions = -1
	for _, p := range worstCaseMemory(cfg).parts {
		if p.what == "TCP ports of the sessions (one each)" {
			assert.False(t, p.unbounded)
			assert.EqualValues(t, 20, p.count)
		}
	}
}

// A configured count so large that count x cost overflows is no bound: it
// must not wrap to a small total and silence the warning.
func TestHugeCountsDoNotWrapTheSum(t *testing.T) {
	cfg := loadConfig(t, defaultsConfig)
	cfg.Edge.MaxConns = 100000000000000 // 1e14, "no practical limit"
	e := worstCaseMemory(cfg)
	assert.Contains(t, e.unbounded(), "edge.max_conns")
	assert.Positive(t, e.total())
	w := memoryWarning(e, 1792<<20)
	assert.Contains(t, w, "no bound")
	// The operator set a value: it is named as too large to count, not as
	// disabled.
	assert.Contains(t, w, "edge.max_conns too large to count")
	assert.NotContains(t, w, "disabled")
	assert.Contains(t, e.String(), "too large to count")
	assert.NotContains(t, e.String(), "disabled")

	// A disabled limit is still named as disabled.
	cfg = loadConfig(t, defaultsConfig)
	cfg.Edge.MaxConns = -1
	e = worstCaseMemory(cfg)
	assert.Contains(t, e.unbounded(), "edge.max_conns")
	assert.Contains(t, e.String(), "no bound (disabled)")
	assert.Contains(t, memoryWarning(e, 1792<<20), "edge.max_conns disabled")

	// An absurd table limit of the web UI makes the unit of the rate-limit
	// term saturate instead of wrapping: that term is too large to count.
	cfg = loadConfig(t, defaultsConfig)
	cfg.Frontend.UserActionsPerHour = math.MaxInt
	e = worstCaseMemory(cfg)
	assert.Contains(t, e.unbounded(), "frontend.rate_limit_max_keys")
	assert.Positive(t, e.total())
	// The operator set a table limit, not the number of keys: the warning
	// names the rate limits.
	w = memoryWarning(e, 1792<<20)
	assert.Contains(t, w, "a rate limit of the web UI (frontend.*_per_*) too large to count")
	assert.NotContains(t, w, "frontend.rate_limit_max_keys too large to count")

	// Both reasons at once: the number of keys disabled and a table limit
	// too large to count. The warning names both.
	cfg.Frontend.RateLimitMaxKeys = -1
	w = memoryWarning(worstCaseMemory(cfg), 1792<<20)
	assert.Contains(t, w, "frontend.rate_limit_max_keys disabled")
	assert.Contains(t, w, "a rate limit of the web UI (frontend.*_per_*) too large to count")

	// The sum itself saturates instead of wrapping.
	big := memoryEstimate{parts: []memoryPart{
		{key: "a", count: 1, unit: math.MaxInt64 - 10},
		{key: "b", count: 1, unit: 100},
	}}
	assert.Equal(t, int64(math.MaxInt64), big.total())
}

// The server makes argon2id hashes with the memory the sum counts.
func TestPasswordHashMemoryMatchesTheHashes(t *testing.T) {
	hash, err := auth.HashPassword("a password of some length")
	require.NoError(t, err)
	m := regexp.MustCompile(`\$m=(\d+),`).FindStringSubmatch(hash)
	require.Len(t, m, 2, hash)
	kib, err := strconv.Atoi(m[1])
	require.NoError(t, err)
	assert.Equal(t, int64(passwordHashMemoryBytes), int64(kib)<<10)
}

// unitSettings reads the [Service] settings of the systemd unit.
func unitSettings(t *testing.T) map[string][]string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "systemd", "tunneld.service"))
	require.NoError(t, err)
	defer f.Close()
	out := map[string][]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			out[k] = append(out[k], v)
		}
	}
	require.NoError(t, sc.Err())
	return out
}

// parseSystemdSize reads a size such as 2G or 1792M (base 1024).
func parseSystemdSize(t *testing.T, s string) int64 {
	t.Helper()
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	require.NoError(t, err)
	return n * mult
}

// parseGoMemLimit reads a GOMEMLIMIT value such as 1792MiB.
func parseGoMemLimit(t *testing.T, s string) int64 {
	t.Helper()
	for suffix, mult := range map[string]int64{"GiB": 1 << 30, "MiB": 1 << 20, "KiB": 1 << 10} {
		if strings.HasSuffix(s, suffix) {
			n, err := strconv.ParseInt(strings.TrimSuffix(s, suffix), 10, 64)
			require.NoError(t, err)
			return n * mult
		}
	}
	t.Fatalf("GOMEMLIMIT %q has no unit", s)
	return 0
}

// The unit's MemoryMax is the one the budget is computed for, and GOMEMLIMIT
// lies between the worst case of the defaults and MemoryMax: the garbage
// collector works harder before the kernel would end the process, and the
// defaults do not trigger the start-up warning.
func TestUnitMemoryLimits(t *testing.T) {
	s := unitSettings(t)
	require.Equal(t, []string{"2G"}, s["MemoryMax"])
	require.Equal(t, int64(unitMemoryMax), parseSystemdSize(t, s["MemoryMax"][0]))

	var goMemLimit string
	for _, env := range s["Environment"] {
		for _, kv := range strings.Fields(env) {
			if v, ok := strings.CutPrefix(strings.Trim(kv, `"`), "GOMEMLIMIT="); ok {
				goMemLimit = v
			}
		}
	}
	require.NotEmpty(t, goMemLimit, "the unit sets GOMEMLIMIT")
	limit := parseGoMemLimit(t, goMemLimit)
	assert.Less(t, limit, int64(unitMemoryMax))
	assert.Greater(t, limit, worstCaseMemory(loadConfig(t, defaultsConfig)).total())
	assert.Empty(t, memoryWarning(worstCaseMemory(loadConfig(t, defaultsConfig)), limit))

	// Nothing in the sandbox drops the variable: no PassEnvironment= or
	// UnsetEnvironment= list.
	assert.Empty(t, s["PassEnvironment"])
	assert.Empty(t, s["UnsetEnvironment"])
}

func TestMemoryWarning(t *testing.T) {
	const limit = 1792 << 20
	cfg := loadConfig(t, defaultsConfig)
	assert.Empty(t, memoryWarning(worstCaseMemory(cfg), limit), "the defaults fit")
	assert.Empty(t, memoryWarning(worstCaseMemory(cfg), math.MaxInt64), "no limit set: nothing to compare with")

	cfg.Edge.MaxConns = 5000
	w := memoryWarning(worstCaseMemory(cfg), limit)
	require.NotEmpty(t, w)
	assert.Contains(t, w, "GOMEMLIMIT")
	assert.Contains(t, w, "1.75 GiB")
	assert.Contains(t, w, "edge.max_conns (5000 x 704 KiB")
	assert.Contains(t, w, "http_server.max_conns")
	assert.Contains(t, w, "MemoryMax")
	assert.True(t, strings.Index(w, "edge.max_conns") < strings.Index(w, "http_server.max_conns"), "largest term first: %s", w)

	cfg.Edge.MaxConns = 0
	cfg.Tunnel.MaxSessions = -1
	w = memoryWarning(worstCaseMemory(cfg), limit)
	assert.Contains(t, w, "no bound")
	assert.Contains(t, w, "tunnel.max_sessions disabled")
}

// runServer logs the warning at start-up, before anything else can fail.
func TestRunServerWarnsAboutMemory(t *testing.T) {
	prev := debug.SetMemoryLimit(64 << 20)
	defer debug.SetMemoryLimit(prev)
	occupied, err := net.Listen("tcp", testports.Loopback+":0")
	require.NoError(t, err)
	defer occupied.Close()
	cfg := loadConfig(t, fmt.Sprintf(`domain: tunnel.test
listen: {tunnel_addr: "127.0.0.1:0", http_addr: %q}
tls: {self_signed_hosts: [tunnel.test]}
auth: {tokens: [twbl_static_token_0001]}
metrics: {addr: ""}
`, occupied.Addr().String()))
	logger, logs := captureLog()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.Error(t, runServer(ctx, cfg, logger))
	assert.Contains(t, logs.String(), "Go memory limit of 64.0 MiB")
}

// The server logs the warning at start-up against the limit in force.
func TestStartupLogsTheMemoryWarning(t *testing.T) {
	prev := debug.SetMemoryLimit(64 << 20)
	defer debug.SetMemoryLimit(prev)
	logger, logs := captureLog()
	warnAboutMemory(loadConfig(t, defaultsConfig), logger)
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "Go memory limit of 64.0 MiB")

	debug.SetMemoryLimit(math.MaxInt64)
	logger, logs = captureLog()
	warnAboutMemory(loadConfig(t, defaultsConfig), logger)
	assert.Empty(t, logs.String(), "no limit set: no warning")
}
