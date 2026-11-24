package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// fullConfig sets every limit and timeout to a value that differs from its
// default and from every other value, so that a setting that reaches the
// wrong option shows up.
const fullConfig = `domain: tunnel.test
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [tunnel.test]
auth:
  csrf_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
database:
  url: "postgres://tunneld:secret@127.0.0.1:5432/tunneld?sslmode=disable"
http_server:
  max_header_bytes: 70001
tunnel:
  handshake_timeout: 11s
  verify_timeout: 6s
  max_unauth_conns: 101
  max_unauth_conns_per_ip: 102
  max_preauth_frame_bytes: 4103
  max_control_frame_bytes: 16104
  accept_backlog: 105
  max_streams_per_session: 106
  max_streams_per_user: 161
  control_burst: 107
  control_refill_per_second: 108
  max_sessions_per_user: 109
  max_sessions: 110
edge:
  max_conns: 20111
  http:
    max_conns_per_tunnel: 112
    max_conns_per_ip: 113
    idle_timeout: 114s
  tcp:
    max_conns_per_tunnel: 115
    max_conns_per_ip: 116
    idle_timeout: 117s
  udp:
    max_flows_per_port: 118
    max_flows_per_ip: 119
    max_flows: 120
    reply_credit: 121
    max_reply_credit: 122
    max_queued_bytes_per_flow: 123
    max_queued_bytes_per_port: 124
    max_queued_bytes: 125
tcp:
  enabled: true
  port_range: {low: 10001, high: 10100}
udp:
  enabled: true
  port_range: {low: 30001, high: 30200}
  flow_idle_timeout: 126s
  flow_buffer_size: 127
limits:
  max_reservations_per_user: 128
  max_tokens_per_user: 129
  max_token_name_length: 130
  max_user_agent_bytes: 131
  min_password_length: 132
  min_admin_password_length: 133
  max_password_bytes: 1134
  hash_concurrency: 135
  hash_wait: 136s
  hash_per_ip: 99
  unverified_account_ttl: 137h
mail:
  from: "noreply@tunnel.test"
  smtp:
    host: "smtp.tunnel.test"
    port: 2525
    username: "user"
    password: "pass"
    auth_required: true
    allow_plaintext: true
    dial_timeout: 138s
    send_timeout: 139s
`

func loadConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tunneld.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	cfg, err := config.Load(path)
	require.NoError(t, err)
	return cfg
}

func TestAcceptorOptionsCarryTheTunnelSettings(t *testing.T) {
	prev := version
	version = "9.8.7"
	defer func() { version = prev }()

	got := acceptorOptions(loadConfig(t, fullConfig))
	assert.Equal(t, acceptor.Options{
		Domain:                 "tunnel.test",
		ServerVersion:          "9.8.7",
		HandshakeTimeout:       11 * time.Second,
		VerifyTimeout:          6 * time.Second,
		MaxUnauthConns:         101,
		MaxUnauthConnsPerIP:    102,
		MaxPreAuthFrameSize:    4103,
		MaxControlFrameSize:    16104,
		AcceptBacklog:          105,
		MaxStreamsPerSession:   106,
		MaxStreamsPerUser:      161,
		ControlBurst:           107,
		ControlRefillPerSecond: 108,
		MaxSessionsPerUser:     109,
		MaxSessions:            110,
	}, got)
}

func TestEdgeOptionsCarryTheEdgeSettings(t *testing.T) {
	cfg := loadConfig(t, fullConfig)
	reg := registry.New()
	logger, _ := captureLog()
	budget := edgeBudget(cfg)
	require.NotNil(t, budget)

	h := edgeHTTPOptions(cfg, reg, logger, budget)
	assert.Equal(t, "tunnel.test", h.Domain)
	assert.Same(t, reg, h.Registry)
	assert.Same(t, logger, h.Logger)
	assert.Equal(t, 112, h.MaxConnsPerTunnel)
	assert.Equal(t, 113, h.MaxConnsPerIP)
	assert.Equal(t, 20111, h.MaxConns)
	assert.Same(t, budget, h.TotalBudget)
	assert.Equal(t, 114*time.Second, h.IdleTimeout)
	assert.Equal(t, 70001, h.MaxHeaderBytes, "one head limit for the server and the edge")

	tc := edgeTCPOptions(cfg, logger, budget)
	require.NotNil(t, tc.Pool)
	assert.Same(t, logger, tc.Logger)
	assert.Equal(t, 115, tc.MaxConnsPerTunnel)
	assert.Equal(t, 116, tc.MaxConnsPerIP)
	assert.Equal(t, 20111, tc.MaxConns)
	assert.Same(t, budget, tc.TotalBudget, "the HTTP and the TCP edge share one budget")
	assert.Equal(t, 117*time.Second, tc.IdleTimeout)
	assert.Empty(t, tc.BindHost, "production listens on all interfaces")

	u := edgeUDPOptions(cfg, logger)
	require.NotNil(t, u.Pool)
	assert.Same(t, logger, u.Logger)
	assert.Equal(t, 126*time.Second, u.IdleTimeout)
	assert.Equal(t, 127, u.BufferSize)
	assert.Equal(t, 5*time.Second, u.SweepInterval)
	assert.Equal(t, 118, u.MaxFlowsPerPort)
	assert.Equal(t, 119, u.MaxFlowsPerIP)
	assert.Equal(t, 120, u.MaxFlows)
	assert.Equal(t, 121, u.ReplyCredit)
	assert.Equal(t, 122, u.MaxReplyCredit)
	assert.Equal(t, 123, u.MaxQueuedBytesPerFlow)
	assert.Equal(t, 124, u.MaxQueuedBytesPerPort)
	assert.Equal(t, 125, u.MaxQueuedBytes)
	assert.Empty(t, u.BindHost)
}

func TestEdgeBudget(t *testing.T) {
	cfg := loadConfig(t, fullConfig)

	cfg.Edge.MaxConns = 0
	b := edgeBudget(cfg)
	require.NotNil(t, b, "the default is one shared budget")
	assert.Equal(t, 1000, budgetCapacity(b))

	cfg.Edge.MaxConns = 7
	assert.Equal(t, 7, budgetCapacity(edgeBudget(cfg)))

	cfg.Edge.MaxConns = -1
	assert.Nil(t, edgeBudget(cfg), "negative disables the shared total")
}

// budgetCapacity counts the slots of b by filling it through a limiter.
func budgetCapacity(b *edgeguard.Budget) int {
	l := edgeguard.NewLimiter(0, 0, 0)
	l.SetBudget(b)
	var releases []func()
	defer func() {
		for _, r := range releases {
			r()
		}
	}()
	for n := 0; n < 100000; n++ {
		release, err := l.Acquire("t", edgeguard.ParseSource("192.0.2.1:1"))
		if err != nil {
			return n
		}
		releases = append(releases, release)
	}
	return -1
}

func TestAccountAndMailOptionsCarryTheirSettings(t *testing.T) {
	cfg := loadConfig(t, fullConfig)
	logger, _ := captureLog()

	assert.Equal(t, mail.SMTPConfig{
		Host: "smtp.tunnel.test", Port: 2525, Username: "user", Password: "pass", From: "noreply@tunnel.test",
		AuthRequired: true, AllowPlaintext: true, DialTimeout: 138 * time.Second, SendTimeout: 139 * time.Second,
	}, smtpConfig(cfg))
	assert.Equal(t, auth.HashLimits{MaxConcurrent: 135, MaxWait: 136 * time.Second}, hashLimits(cfg))
	assert.Equal(t, users.Options{MinPasswordLength: 132, MinAdminPasswordLength: 133, MaxPasswordBytes: 1134}, userOptions(cfg))
	assert.Equal(t, tokens.Options{MaxActivePerUser: 129, MaxNameLength: 130}, tokenOptions(cfg))
	for _, c := range []struct {
		signup string
		want   bool
		mode   string // frontend.Options.SignupMode
	}{{"approval", true, "approval"}, {"closed", true, "closed"}, {"", false, "open"}} {
		cfg.Auth.Signup = c.signup
		assert.Equal(t, c.want, tokenOptions(cfg).RequireApproved, "auth.signup %q", c.signup)
		assert.Equal(t, c.mode, frontendOptions(cfg).SignupMode, "auth.signup %q", c.signup)
	}
	assert.Equal(t, reservations.Options{MaxSubdomainsPerUser: 128}, reservationOptions(cfg))
	assert.Equal(t, sessions.Options{MaxUserAgentBytes: 131}, sessionOptions(cfg))
	r := reaperOptions(cfg, logger)
	assert.Equal(t, 137*time.Hour, r.UnverifiedAccountTTL)
	assert.Same(t, logger, r.Logger)
	assert.Zero(t, r.Interval, "the reaper keeps its own interval")
}

// The reaper deletes accounts that wait for approval only in approval and
// closed mode. In open mode (the default) every account that was signed up
// has approved_at NULL: if the rule ran there, the first sweep would delete
// every account older than 30 days that holds no token or reservation.
func TestPendingAccountTTLIsOffInOpenMode(t *testing.T) {
	cfg := loadConfig(t, fullConfig)
	logger, _ := captureLog()
	for _, c := range []struct {
		signup string
		ttl    time.Duration // limits.pending_account_ttl
		want   time.Duration
	}{
		{"", 0, 0},
		{"", 721 * time.Hour, 0},
		{"open", 0, 0},
		{"open", 721 * time.Hour, 0},
		{"approval", 0, 720 * time.Hour},
		{"closed", 0, 720 * time.Hour},
		{"closed", 721 * time.Hour, 721 * time.Hour},
		{"approval", -time.Second, 0},
	} {
		cfg.Auth.Signup, cfg.Limits.PendingAccountTTL = c.signup, c.ttl
		assert.Equal(t, c.want, pendingAccountTTL(cfg), "auth.signup %q, pending_account_ttl %s", c.signup, c.ttl)
		assert.Equal(t, c.want, reaperOptions(cfg, logger).PendingAccountTTL, "reaper options: auth.signup %q, pending_account_ttl %s", c.signup, c.ttl)
	}
}

func TestSMTPAllowPlaintextIsOffUnlessSet(t *testing.T) {
	cfg := loadConfig(t, fullConfig)
	cfg.Mail.SMTP.AllowPlaintext = false
	assert.False(t, smtpConfig(cfg).AllowPlaintext)
}

func TestFrontendPortRangesAreThoseOfTheEnabledEdges(t *testing.T) {
	cfg := loadConfig(t, fullConfig)
	tcp, udp := frontendPortRanges(cfg)
	assert.Equal(t, frontend.PortRange{Low: 10001, High: 10100}, tcp)
	assert.Equal(t, frontend.PortRange{Low: 30001, High: 30200}, udp)

	cfg.TCP.Enabled, cfg.UDP.Enabled = false, false
	tcp, udp = frontendPortRanges(cfg)
	assert.Zero(t, tcp)
	assert.Zero(t, udp)
}

func TestFrontendOptionsCarryTheWebUISettings(t *testing.T) {
	cfg := loadConfig(t, fullConfig+`frontend:
  public_base_url: "https://app.tunnel.test"
  login_failures_per_account: 140
  login_failures_per_ip: 141
  login_failure_window: 142m
  logins_per_account: 151
  signups_per_ip: 143
  signup_window: 144m
  reset_requests_per_ip: 145
  reset_requests_per_account: 146
  reset_request_window: 147m
  rate_limit_max_keys: 148
  max_request_body_bytes: 149
  user_actions_per_hour: 152
  unauthenticated_audit_rows_per_minute: 153
`)
	cfg.Mail.QueueSize = 150
	o := frontendOptions(cfg)
	assert.Equal(t, "tunnel.test", o.Domain)
	assert.True(t, o.CSRFSecure)
	assert.Equal(t, cfg.CSRFKeyBytes(), o.CSRFKey)
	assert.Equal(t, "https://app.tunnel.test", o.PublicBaseURL)
	assert.Equal(t, frontend.PortRange{Low: 10001, High: 10100}, o.TCPPortRange)
	assert.Equal(t, frontend.PortRange{Low: 30001, High: 30200}, o.UDPPortRange)
	assert.Equal(t, 140, o.LoginFailuresPerAccount)
	assert.Equal(t, 141, o.LoginFailuresPerIP)
	assert.Equal(t, 142*time.Minute, o.LoginFailureWindow)
	assert.Equal(t, 143, o.SignupsPerIP)
	assert.Equal(t, 144*time.Minute, o.SignupWindow)
	assert.Equal(t, 145, o.ResetRequestsPerIP)
	assert.Equal(t, 146, o.ResetRequestsPerAccount)
	assert.Equal(t, 147*time.Minute, o.ResetRequestWindow)
	assert.Equal(t, 148, o.RateLimitMaxKeys)
	assert.Equal(t, int64(149), o.MaxRequestBodyBytes)
	assert.Equal(t, 150, o.MailQueueSize)
	assert.Equal(t, 99, o.HashPerIP, "limits.hash_per_ip")
	assert.Equal(t, 151, o.LoginsPerAccount)
	assert.Equal(t, 152, o.UserActionsPerHour)
	assert.Equal(t, 153, o.UnauthenticatedAuditRowsPerMinute)
}

// Unset, limits.hash_per_ip follows the effective limits.hash_concurrency
// C: min(2, max(1, C/2)), so that a lowered C does not let one address hold
// every slot (except with C = 1). A set value is passed on as it is.
func TestHashPerIPFollowsHashConcurrency(t *testing.T) {
	const base = `domain: tunnel.test
listen: {tunnel_addr: ":7443", http_addr: ":443"}
tls: {self_signed_hosts: [tunnel.test]}
auth: {tokens: [twbl_static_token_0001]}
`
	for _, c := range []struct {
		limits string
		want   int
	}{
		{"", 2},                     // C unset: 4
		{"hash_concurrency: 8", 2},  // capped at the frontend's default
		{"hash_concurrency: 4", 2},  // half
		{"hash_concurrency: 3", 1},  // half, rounded down
		{"hash_concurrency: 2", 1},  // half
		{"hash_concurrency: 1", 1},  // at least 1: the address holds the only slot
		{"hash_concurrency: -1", 0}, // no process-wide limit: the frontend's default
		// A set value is kept, negative (off) included.
		{"hash_concurrency: 8, hash_per_ip: 3", 3},
		{"hash_concurrency: 2, hash_per_ip: 1", 1},
		{"hash_per_ip: 3", 3},
		{"hash_concurrency: 2, hash_per_ip: -1", -1},
		{"hash_concurrency: -1, hash_per_ip: 9", 9},
		{"hash_concurrency: 135, hash_per_ip: 99", 99},
	} {
		body := base
		if c.limits != "" {
			body += "limits: {" + c.limits + "}\n"
		}
		assert.Equal(t, c.want, frontendOptions(loadConfig(t, body)).HashPerIP, "limits: {%s}", c.limits)
	}
}

func TestDefaultConfigLeavesThePackageDefaults(t *testing.T) {
	cfg := loadConfig(t, `domain: tunnel.test
listen: {tunnel_addr: ":7443", http_addr: ":443"}
tls: {self_signed_hosts: [tunnel.test]}
auth: {tokens: [twbl_static_token_0001]}
`)
	opts := acceptorOptions(cfg)
	opts.ServerVersion = ""
	assert.Equal(t, acceptor.Options{Domain: "tunnel.test"}, opts, "zero everywhere: each package applies its defaults")
	assert.Equal(t, 1000, budgetCapacity(edgeBudget(cfg)))
	assert.Equal(t, mail.SMTPConfig{}, smtpConfig(cfg))
}
