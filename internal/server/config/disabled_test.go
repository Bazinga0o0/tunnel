package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// disabledKeys are the keys of the tunnel, edge, http_server and mail
// sections whose negative value switches a protection off, with the YAML that
// sets them negative.
var disabledKeys = map[string]string{
	"tunnel.handshake_timeout":           "tunnel:\n  handshake_timeout: -1s\n",
	"tunnel.verify_timeout":              "tunnel:\n  verify_timeout: -1s\n",
	"tunnel.max_unauth_conns":            "tunnel:\n  max_unauth_conns: -1\n",
	"tunnel.max_unauth_conns_per_ip":     "tunnel:\n  max_unauth_conns_per_ip: -1\n",
	"tunnel.max_preauth_frame_bytes":     "tunnel:\n  max_preauth_frame_bytes: -1\n",
	"tunnel.max_control_frame_bytes":     "tunnel:\n  max_control_frame_bytes: -1\n",
	"tunnel.accept_backlog":              "tunnel:\n  accept_backlog: -1\n",
	"tunnel.max_streams_per_session":     "tunnel:\n  max_streams_per_session: -1\n",
	"tunnel.max_streams_per_user":        "tunnel:\n  max_streams_per_user: -1\n",
	"tunnel.control_burst":               "tunnel:\n  control_burst: -1\n",
	"tunnel.control_refill_per_second":   "tunnel:\n  control_refill_per_second: -1\n",
	"tunnel.max_sessions_per_user":       "tunnel:\n  max_sessions_per_user: -1\n",
	"tunnel.max_sessions":                "tunnel:\n  max_sessions: -1\n",
	"edge.max_conns":                     "edge:\n  max_conns: -1\n",
	"edge.http.max_conns_per_tunnel":     "edge:\n  http:\n    max_conns_per_tunnel: -1\n",
	"edge.http.max_conns_per_ip":         "edge:\n  http:\n    max_conns_per_ip: -1\n",
	"edge.http.idle_timeout":             "edge:\n  http:\n    idle_timeout: -1s\n",
	"edge.tcp.max_conns_per_tunnel":      "tcp:\n  enabled: true\nedge:\n  tcp:\n    max_conns_per_tunnel: -1\n",
	"edge.tcp.max_conns_per_ip":          "tcp:\n  enabled: true\nedge:\n  tcp:\n    max_conns_per_ip: -1\n",
	"edge.tcp.idle_timeout":              "tcp:\n  enabled: true\nedge:\n  tcp:\n    idle_timeout: -1s\n",
	"edge.udp.max_flows_per_port":        "udp:\n  enabled: true\nedge:\n  udp:\n    max_flows_per_port: -1\n",
	"edge.udp.max_flows_per_ip":          "udp:\n  enabled: true\nedge:\n  udp:\n    max_flows_per_ip: -1\n",
	"edge.udp.max_flows":                 "udp:\n  enabled: true\nedge:\n  udp:\n    max_flows: -1\n",
	"edge.udp.reply_credit":              "udp:\n  enabled: true\nedge:\n  udp:\n    reply_credit: -1\n",
	"edge.udp.max_reply_credit":          "udp:\n  enabled: true\nedge:\n  udp:\n    max_reply_credit: -1\n",
	"edge.udp.max_queued_bytes_per_flow": "udp:\n  enabled: true\nedge:\n  udp:\n    max_queued_bytes_per_flow: -1\n",
	"edge.udp.max_queued_bytes_per_port": "udp:\n  enabled: true\nedge:\n  udp:\n    max_queued_bytes_per_port: -1\n",
	"edge.udp.max_queued_bytes":          "udp:\n  enabled: true\nedge:\n  udp:\n    max_queued_bytes: -1\n",
	"http_server.max_conns":              "http_server:\n  max_conns: -1\n",
	"http_server.max_conns_per_ip":       "http_server:\n  max_conns_per_ip: -1\n",
	"http_server.frontend_read_timeout":  "http_server:\n  frontend_read_timeout: -1s\n",
	"http_server.frontend_write_timeout": "http_server:\n  frontend_write_timeout: -1s\n",
	"mail.smtp.dial_timeout":             "mail:\n  smtp:\n    dial_timeout: -1s\n",
}

// disabledAccountKeys are the keys of the frontend and limits sections whose
// negative value switches a protection off. The windows of the frontend
// limits are not among them (validation refuses a negative window), nor is
// limits.unverified_account_ttl (the rule is off unless set).
var disabledAccountKeys = map[string]string{
	"frontend.login_failures_per_account": "frontend:\n  login_failures_per_account: -1\n",
	"frontend.login_failures_per_ip":      "frontend:\n  login_failures_per_ip: -1\n",
	"frontend.logins_per_account":         "frontend:\n  logins_per_account: -1\n",
	"frontend.signups_per_ip":             "frontend:\n  signups_per_ip: -1\n",
	"frontend.reset_requests_per_ip":      "frontend:\n  reset_requests_per_ip: -1\n",
	"frontend.reset_requests_per_account": "frontend:\n  reset_requests_per_account: -1\n",
	"frontend.user_actions_per_hour":      "frontend:\n  user_actions_per_hour: -1\n",
	"frontend.rate_limit_max_keys":        "frontend:\n  rate_limit_max_keys: -1\n",
	"frontend.max_request_body_bytes":     "frontend:\n  max_request_body_bytes: -1\n",
	"limits.max_reservations_per_user":    "limits:\n  max_reservations_per_user: -1\n",
	"limits.max_tokens_per_user":          "limits:\n  max_tokens_per_user: -1\n",
	"limits.max_token_name_length":        "limits:\n  max_token_name_length: -1\n",
	"limits.max_user_agent_bytes":         "limits:\n  max_user_agent_bytes: -1\n",
	"limits.min_password_length":          "limits:\n  min_password_length: -1\n",
	"limits.min_admin_password_length":    "limits:\n  min_admin_password_length: -1\n",
	"limits.max_password_bytes":           "limits:\n  max_password_bytes: -1\n",
	"limits.hash_concurrency":             "limits:\n  hash_concurrency: -1\n",
	"limits.hash_wait":                    "limits:\n  hash_wait: -1s\n",
	"limits.hash_per_ip":                  "limits:\n  hash_per_ip: -1\n",

	"frontend.unauthenticated_audit_rows_per_minute": "frontend:\n  unauthenticated_audit_rows_per_minute: -1\n",
}

// The keys of the web UI and the accounts are warned about in the same way.
func TestEachDisabledAccountProtectionIsWarnedAbout(t *testing.T) {
	for key, section := range disabledAccountKeys {
		t.Run(key, func(t *testing.T) {
			cfg := mustLoad(t, staticBase+section)
			require.Len(t, cfg.Warnings, 1, "%v", cfg.Warnings)
			assert.True(t, strings.HasPrefix(cfg.Warnings[0], key+" is negative"), cfg.Warnings[0])
		})
	}
	// Settings that are off by default or cannot be negative warn about
	// nothing.
	for _, section := range []string{
		"limits:\n  unverified_account_ttl: -1h\n",
		"frontend:\n  login_failure_window: 0s\n",
	} {
		assert.Empty(t, mustLoad(t, staticBase+section).Warnings, section)
	}
}

// The warning for frontend.user_actions_per_hour says what the budget bounds:
// the changes of tokens and reservations and the password change on the
// settings page (limitUserActions in internal/server/frontend).
func TestTheUserActionsWarningNamesWhatTheBudgetBounds(t *testing.T) {
	cfg := mustLoad(t, staticBase+disabledAccountKeys["frontend.user_actions_per_hour"])
	require.Len(t, cfg.Warnings, 1, "%v", cfg.Warnings)
	for _, part := range []string{"token", "reservation", "password change"} {
		assert.Contains(t, cfg.Warnings[0], part)
	}
}

// A negative value switches a limit off, silently until now. Each protection
// switched off gets one start-up warning that names its key.
func TestEachDisabledProtectionIsWarnedAbout(t *testing.T) {
	for key, section := range disabledKeys {
		t.Run(key, func(t *testing.T) {
			cfg := mustLoad(t, staticBase+section)
			require.Len(t, cfg.Warnings, 1, "%v", cfg.Warnings)
			assert.True(t, strings.HasPrefix(cfg.Warnings[0], key+" is negative"), cfg.Warnings[0])
		})
	}
}

// Keys of an edge that is off change nothing and warn about nothing.
func TestDisabledLimitsOfAnEdgeThatIsOffAreNotWarnedAbout(t *testing.T) {
	cfg := mustLoad(t, staticBase+"edge:\n  tcp:\n    idle_timeout: -1s\n  udp:\n    max_flows: -1\n")
	assert.Empty(t, cfg.Warnings)
}

// Several at once: one warning each.
func TestSeveralDisabledProtections(t *testing.T) {
	cfg := mustLoad(t, staticBase+"tunnel:\n  handshake_timeout: -1s\n  max_sessions: -1\nhttp_server:\n  max_conns: -1\n")
	assert.Len(t, cfg.Warnings, 3)
}
