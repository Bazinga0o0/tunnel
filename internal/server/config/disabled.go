package config

import "fmt"

// disabledProtection is a key whose negative value switches a protection off.
type disabledProtection struct {
	key  string
	off  bool   // the configured value is negative
	what string // what the negative value switches off
}

// disabledProtectionWarnings returns one warning for every protection of the
// tunnel listener, the edges, the public HTTPS listener, the mail transport,
// the web UI and the accounts that the configuration switches off with a
// negative value. The
// keys of an edge that is off are left out: they change nothing. (A negative
// tunnel.revalidate_interval has a warning of its own at start-up, in
// database mode, where the revalidation runs.)
func (c *Config) disabledProtectionWarnings() []string {
	t, e, h := c.Tunnel, c.Edge, c.HTTPServer
	list := []disabledProtection{
		{"tunnel.handshake_timeout", t.HandshakeTimeout < 0, "the deadline from accept to login"},
		{"tunnel.verify_timeout", t.VerifyTimeout < 0, "the time limit of a token check and of a reservation lookup"},
		{"tunnel.max_unauth_conns", t.MaxUnauthConns < 0, "the limit on tunnel connections that have not logged in"},
		{"tunnel.max_unauth_conns_per_ip", t.MaxUnauthConnsPerIP < 0, "the limit on such connections per source address"},
		{"tunnel.max_preauth_frame_bytes", t.MaxPreAuthFrameBytes < 0, "the frame size limit before login (the protocol ceiling of 1 MiB stays)"},
		{"tunnel.max_control_frame_bytes", t.MaxControlFrameBytes < 0, "the frame size limit after login (the protocol ceiling of 1 MiB stays)"},
		{"tunnel.accept_backlog", t.AcceptBacklog < 0, "the reduced accept backlog (yamux keeps its own 256)"},
		{"tunnel.max_streams_per_session", t.MaxStreamsPerSession < 0, "the limit on the streams of one session"},
		{"tunnel.max_streams_per_user", t.MaxStreamsPerUser < 0, "the limit on the streams of all sessions of one user"},
		{"tunnel.control_burst", t.ControlBurst < 0, "the throttle on control messages"},
		{"tunnel.control_refill_per_second", t.ControlRefillPerSecond < 0, "the throttle on control messages"},
		{"tunnel.max_sessions_per_user", t.MaxSessionsPerUser < 0, "the limit on the sessions of one user"},
		{"tunnel.max_sessions", t.MaxSessions < 0, "the limit on tunnel sessions in total"},
		{"edge.max_conns", e.MaxConns < 0, "the limit on visitor connections of the HTTP and TCP tunnels in total"},
		{"edge.http.max_conns_per_tunnel", e.HTTP.MaxConnsPerTunnel < 0, "the limit on the visitor connections of one HTTP tunnel"},
		{"edge.http.max_conns_per_ip", e.HTTP.MaxConnsPerIP < 0, "the limit on the connections of one visitor address to an HTTP tunnel"},
		{"edge.http.idle_timeout", e.HTTP.IdleTimeout < 0, "the idle timeout of HTTP tunnel connections"},
		{"http_server.max_conns", h.MaxConns < 0, "the limit on public HTTPS connections in total"},
		{"http_server.max_conns_per_ip", h.MaxConnsPerIP < 0, "the limit on public HTTPS connections per source address"},
		{"http_server.frontend_read_timeout", h.FrontendReadTimeout < 0, "the read deadline of web UI requests"},
		{"http_server.frontend_write_timeout", h.FrontendWriteTimeout < 0, "the write deadline of web UI responses"},
		{"mail.smtp.dial_timeout", c.Mail.SMTP.DialTimeout < 0, "the separate connect timeout of mail delivery (mail.smtp.send_timeout still bounds it)"},
	}
	// The web UI and the accounts. The windows of the frontend limits cannot
	// be negative (validation refuses them), and limits.unverified_account_ttl
	// is off unless set, so neither appears here.
	f, l := c.Frontend, c.Limits
	list = append(list,
		disabledProtection{"frontend.login_failures_per_account", f.LoginFailuresPerAccount < 0, "the limit on failed logins per typed address"},
		disabledProtection{"frontend.login_failures_per_ip", f.LoginFailuresPerIP < 0, "the limit on failed logins per client address"},
		disabledProtection{"frontend.logins_per_account", f.LoginsPerAccount < 0, "the limit on successful logins per typed address"},
		disabledProtection{"frontend.signups_per_ip", f.SignupsPerIP < 0, "the limit on sign-ups per client address"},
		disabledProtection{"frontend.reset_requests_per_ip", f.ResetRequestsPerIP < 0, "the limit on password-reset requests per client address"},
		disabledProtection{"frontend.reset_requests_per_account", f.ResetRequestsPerAccount < 0, "the limits on password-reset requests and reset mails per address"},
		disabledProtection{"frontend.user_actions_per_hour", f.UserActionsPerHour < 0, "the limit per user on token and reservation changes and password changes on the settings page"},
		disabledProtection{"frontend.rate_limit_max_keys", f.RateLimitMaxKeys < 0, "the size bound of the web UI's rate-limit tables: they grow without bound"},
		disabledProtection{"frontend.max_request_body_bytes", f.MaxRequestBodyBytes < 0, "the size limit of web UI request bodies"},
		disabledProtection{"frontend.unauthenticated_audit_rows_per_minute", f.UnauthenticatedAuditRowsPerMinute < 0, "the bound on audit rows that requests without a login cause: audit_log grows as fast as they come"},
		disabledProtection{"limits.max_reservations_per_user", l.MaxReservationsPerUser < 0, "the limit on subdomain reservations per user"},
		disabledProtection{"limits.max_tokens_per_user", l.MaxTokensPerUser < 0, "the limit on active API tokens per user"},
		disabledProtection{"limits.max_token_name_length", l.MaxTokenNameLength < 0, "the length limit of token names"},
		disabledProtection{"limits.max_user_agent_bytes", l.MaxUserAgentBytes < 0, "the length limit of the User-Agent stored with a web session"},
		disabledProtection{"limits.min_password_length", l.MinPasswordLength < 0, "the minimum length of user passwords"},
		disabledProtection{"limits.min_admin_password_length", l.MinAdminPasswordLength < 0, "the minimum length of passwords an admin sets"},
		disabledProtection{"limits.max_password_bytes", l.MaxPasswordBytes < 0, "the maximum length of passwords"},
		disabledProtection{"limits.hash_concurrency", l.HashConcurrency < 0, "the limit on password hashes at a time (64 MiB each)"},
		disabledProtection{"limits.hash_wait", l.HashWait < 0, "the time limit of the wait for a password-hash slot"},
		disabledProtection{"limits.hash_per_ip", l.HashPerIP < 0, "the limit on password-hash work in flight per client address"},
	)
	if c.TCP.Enabled {
		list = append(list,
			disabledProtection{"edge.tcp.max_conns_per_tunnel", e.TCP.MaxConnsPerTunnel < 0, "the limit on the visitor connections of one TCP tunnel"},
			disabledProtection{"edge.tcp.max_conns_per_ip", e.TCP.MaxConnsPerIP < 0, "the limit on the connections of one visitor address to a TCP tunnel"},
			disabledProtection{"edge.tcp.idle_timeout", e.TCP.IdleTimeout < 0, "the idle timeout of TCP tunnel connections"},
		)
	}
	if c.UDP.Enabled {
		u := e.UDP
		list = append(list,
			disabledProtection{"edge.udp.max_flows_per_port", u.MaxFlowsPerPort < 0, "the limit on the flows of one UDP tunnel"},
			disabledProtection{"edge.udp.max_flows_per_ip", u.MaxFlowsPerIP < 0, "the limit on the flows of one visitor address to a UDP tunnel"},
			disabledProtection{"edge.udp.max_flows", u.MaxFlows < 0, "the limit on UDP flows in total"},
			disabledProtection{"edge.udp.reply_credit", u.ReplyCredit < 0, "the reply credit: a UDP tunnel can send any number of datagrams to a forged sender"},
			disabledProtection{"edge.udp.max_reply_credit", u.MaxReplyCredit < 0, "the cap on the reply credit a flow can save up"},
			disabledProtection{"edge.udp.max_queued_bytes_per_flow", u.MaxQueuedBytesPerFlow < 0, "the byte budget of the datagrams one flow queues"},
			disabledProtection{"edge.udp.max_queued_bytes_per_port", u.MaxQueuedBytesPerPort < 0, "the byte budget of the datagrams one UDP tunnel queues"},
			disabledProtection{"edge.udp.max_queued_bytes", u.MaxQueuedBytes < 0, "the byte budget of the datagrams all UDP tunnels queue"},
		)
	}
	var out []string
	for _, p := range list {
		if p.off {
			out = append(out, fmt.Sprintf("%s is negative, which switches off %s", p.key, p.what))
		}
	}
	return out
}
