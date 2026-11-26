// Package config loads and validates the tunneld server configuration.
//
// Settings that bound a resource (limits and timeouts) share one convention:
// an absent key or zero selects the default named on the field, and a
// negative value switches the limit off where the package that enforces it
// allows that. Validation refuses values a package would not honour as
// written, so that the file always means what it says. Unknown keys are an
// error: a misspelt or misplaced key would otherwise be ignored silently.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level server config.
type Config struct {
	Domain     string     `yaml:"domain"`
	Listen     Listen     `yaml:"listen"`
	TLS        TLS        `yaml:"tls"`
	Auth       Auth       `yaml:"auth"`
	Database   Database   `yaml:"database"`
	TCP        TCP        `yaml:"tcp"`
	UDP        UDP        `yaml:"udp"`
	Mail       Mail       `yaml:"mail"`
	Frontend   Frontend   `yaml:"frontend"`
	Metrics    Metrics    `yaml:"metrics"`
	HTTPServer HTTPServer `yaml:"http_server"`
	Tunnel     Tunnel     `yaml:"tunnel"`
	Edge       Edge       `yaml:"edge"`
	Limits     Limits     `yaml:"limits"`
	Services   []Service  `yaml:"services,omitempty"`
	ServiceAPI ServiceAPI `yaml:"service_api"`

	// Warnings are problems Load found that do not stop the server, for
	// example a config file other users can read. The server logs them at
	// start-up.
	Warnings []string `yaml:"-"`

	// Path is the file Load read, made absolute where possible; empty for a
	// config that did not come from a file. Commands the server suggests in
	// its log name it.
	Path string `yaml:"-"`
}

// DefaultMetricsAddr is the metrics address when metrics.addr is absent.
const DefaultMetricsAddr = "127.0.0.1:9090"

// Metrics configures the Prometheus metrics HTTP endpoint.
type Metrics struct {
	// Addr is the bind address of the endpoint. Absent selects
	// DefaultMetricsAddr; an empty string disables the endpoint. The host
	// must be a loopback address (or "localhost") unless AllowNonLoopback
	// is set, because the endpoint has no authentication.
	Addr *string `yaml:"addr"`
	// AllowNonLoopback permits an address other hosts can reach.
	AllowNonLoopback bool `yaml:"allow_non_loopback"`
}

// Address returns the address the endpoint binds to, or "" when it is
// disabled.
func (m Metrics) Address() string {
	if m.Addr == nil {
		return DefaultMetricsAddr
	}
	return *m.Addr
}

// Service is a registered service: HTTPS requests to <Subdomain>.<domain>
// go, once their tunnel API token has been checked, to Upstream on this
// machine. Services need database.url.
type Service struct {
	// Name identifies the service in logs, audit rows and the service API:
	// 1 to 32 characters of a-z, 0-9 and "-", unique.
	Name string `yaml:"name"`
	// Subdomain is one DNS label (lower case), not "app" and unique. With
	// tls.acme, tls.acme.domains must cover <subdomain>.<domain>.
	Subdomain string `yaml:"subdomain"`
	// Upstream is the base URL of the service: http:// with a loopback host
	// and a port, without a path, query or user name.
	Upstream string `yaml:"upstream"`
	// SecretFile is the absolute path of the file with the service's secret
	// for the service API. tunneld reads it at start-up, not when the config
	// is loaded (the admin CLI loads the config too).
	SecretFile string `yaml:"secret_file"`
	// TCPPorts are ports of tcp.port_range whose holder the service sets
	// through the service API; a port belongs to one service only. They need
	// tcp.enabled and service_api.addr.
	TCPPorts []int `yaml:"tcp_ports"`
	// MaxRequestBodyBytes bounds a request body to the service. Zero selects
	// 64 MiB (67108864), at most 256 MiB (268435456); negative values are
	// refused.
	MaxRequestBodyBytes int64 `yaml:"max_request_body_bytes"`
	// Directory opts the service into the directory (GET /api/v1/directory on
	// the web UI host), which signed-in accounts can read. Without it, or
	// with listed: false, the service is not shown. The fields can be
	// reloaded with SIGHUP.
	Directory Directory `yaml:"directory"`
}

// Directory is the public listing of a service.
type Directory struct {
	// Listed makes the service appear in the directory. Default false.
	Listed bool `yaml:"listed"`
	// Title is the display name: required when listed, at most
	// MaxDirectoryTitleRunes characters.
	Title string `yaml:"title"`
	// Description is optional, at most MaxDirectoryDescriptionRunes
	// characters. Title and description are plain text: no control or
	// formatting characters, no line breaks.
	Description string `yaml:"description"`
}

// Limits of the directory texts, in characters.
const (
	MaxDirectoryTitleRunes       = 80
	MaxDirectoryDescriptionRunes = 400
)

// ServiceAPI configures the service API, through which a service sets the
// holder of its TCP ports.
type ServiceAPI struct {
	// Addr is the bind address, host:port with a loopback host: the API
	// must not be reachable from other machines. Required as soon as a
	// service has tcp_ports; tcp.port_range and udp.port_range must not
	// contain its port.
	Addr string `yaml:"addr"`
}

// Mail configures outbound transactional email. When SMTP.Host is empty the
// server and admin CLI treat the mailer as unavailable.
type Mail struct {
	// From is the sender of every mail. With SMTP.Host set it is required
	// and must be a plain address (it goes into MAIL FROM as it is).
	From string `yaml:"from"`
	// QueueSize is the number of mails the web UI keeps waiting for the SMTP
	// server; a mail that does not fit is dropped and logged. Zero selects
	// the default of the web UI (256), at most 4096. Negative values are
	// refused.
	QueueSize int      `yaml:"queue_size"`
	SMTP      MailSMTP `yaml:"smtp"`
}

// MailSMTP configures the SMTP transport.
type MailSMTP struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Username     string `yaml:"username,omitempty"`
	Password     string `yaml:"password,omitempty"`
	AuthRequired bool   `yaml:"auth_required,omitempty"`
	// AllowPlaintext permits delivery without TLS when the server offers no
	// STARTTLS. Only for a mail catcher on the same machine (Mailhog);
	// the server logs a warning at start-up when it is set.
	AllowPlaintext bool `yaml:"allow_plaintext"`
	// DialTimeout bounds the TCP connect to the SMTP server. Zero selects
	// 10 s, negative leaves the connect to SendTimeout.
	DialTimeout time.Duration `yaml:"dial_timeout"`
	// SendTimeout bounds one delivery from connect to QUIT. Zero selects
	// 30 s; negative values are refused, so that a delivery always has a
	// bound.
	SendTimeout time.Duration `yaml:"send_timeout"`
}

// Frontend configures the web UI (app.<domain>).
type Frontend struct {
	// PublicBaseURL is the user-facing base URL (e.g. "https://app.example.org")
	// used when composing links in transactional emails. It must be an
	// https URL; http is accepted only for localhost and loopback
	// addresses. Empty skips email dispatch.
	PublicBaseURL string `yaml:"public_base_url"`

	// Rate limits of the web UI. Counts: zero selects the default, negative
	// disables the limit. Windows: zero selects the default; negative
	// values are refused.
	LoginFailuresPerAccount int           `yaml:"login_failures_per_account"` // 10
	LoginFailuresPerIP      int           `yaml:"login_failures_per_ip"`      // 30
	LoginFailureWindow      time.Duration `yaml:"login_failure_window"`       // 15m
	// LoginsPerAccount bounds the successful logins of one address within
	// login_failure_window: only a login whose password matched and whose
	// session was stored counts, wrong passwords never do. It bounds how
	// fast one account creates sessions and audit rows; switching it off
	// removes that bound. Default 30.
	LoginsPerAccount        int           `yaml:"logins_per_account"`
	SignupsPerIP            int           `yaml:"signups_per_ip"`             // 5
	SignupWindow            time.Duration `yaml:"signup_window"`              // 1h
	ResetRequestsPerIP      int           `yaml:"reset_requests_per_ip"`      // 3
	ResetRequestsPerAccount int           `yaml:"reset_requests_per_account"` // 3
	ResetRequestWindow      time.Duration `yaml:"reset_request_window"`       // 1h
	RateLimitMaxKeys        int           `yaml:"rate_limit_max_keys"`        // frontend.DefaultRateLimitMaxKeys
	// MaxRequestBodyBytes bounds a request body of the web UI. Zero selects
	// 64 KiB, negative removes the size limit (multipart stays refused).
	MaxRequestBodyBytes int64 `yaml:"max_request_body_bytes"`
	// UserActionsPerHour bounds the mutating actions of the user area
	// (create and revoke a token, reserve and release a name, change the
	// password, together) per signed-in user and hour. Default 120.
	UserActionsPerHour int `yaml:"user_actions_per_hour"`
	// UnauthenticatedAuditRowsPerMinute bounds the audit rows that requests
	// without a login cause (failed logins, password-reset requests),
	// together per minute; the rows over it are counted in one summary row
	// per minute. Default 120; negative switches the bound off.
	UnauthenticatedAuditRowsPerMinute int `yaml:"unauthenticated_audit_rows_per_minute"`
}

// Defaults of the public HTTPS server (HTTPServer).
const (
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultIdleTimeout       = 120 * time.Second
	DefaultMaxHeaderBytes    = 64 << 10
	// DefaultMaxConns bounds the public connections to about 146 MiB at
	// HTTPServer.ConnMemoryBytes each with the default head size (see
	// cmd/tunneld/memory.go for the whole budget). It leaves room for the
	// web UI above edge.max_conns (1000).
	DefaultMaxConns             = 1100
	DefaultMaxConnsPerIP        = 128
	DefaultFrontendReadTimeout  = 15 * time.Second
	DefaultFrontendWriteTimeout = 30 * time.Second
)

// PublicConnMemoryBytes is the memory of one connection on the public HTTPS
// listener after the TLS handshake, without a request head that is being
// read (see HTTPServer.ConnMemoryBytes). Measured
// (cmd/tunneld/memory_measure_test.go, go1.27.4): 30 KiB for an idle
// connection; rounded up to 40 KiB.
const PublicConnMemoryBytes = 40 << 10

// TLSHandshakeMemoryBytes is the memory counted for one connection inside the
// TLS handshake, on the public listener and on the tunnel listener alike:
// crypto/tls accepts handshake messages of up to 64 KiB and holds what has
// arrived of one plus the record being read. Measured
// (cmd/tunneld/memory_measure_test.go, go1.27.4): 114-115 KiB for a
// connection that stops a few bytes before the end of a ClientHello of
// almost 64 KiB; counted at 128 KiB.
const TLSHandshakeMemoryBytes = 128 << 10

// ConnMemoryBytes returns the memory counted for one connection of the
// public listener with these settings: PublicConnMemoryBytes plus one and a
// half times max_header_bytes for an unfinished request head (measured:
// 116 KiB for a connection with 60 KiB of a head), and at least
// TLSHandshakeMemoryBytes, which a connection can hold inside the handshake
// whatever max_header_bytes is. The tunnel stream of an HTTP tunnel
// connection is counted on its own (edgetcp.ConnMemoryBytes).
func (h HTTPServer) ConnMemoryBytes() int64 {
	h = h.Resolved()
	return max(TLSHandshakeMemoryBytes, PublicConnMemoryBytes+int64(h.MaxHeaderBytes)*3/2)
}

// minHeaderBytes is the smallest max_header_bytes; the HTTP edge raises
// anything smaller to it.
const minHeaderBytes = 4096

// HTTPServer configures the public HTTPS listener (listen.http_addr), which
// serves the web UI and the HTTP tunnels. Zero selects the default, negative
// disables, except ReadHeaderTimeout, IdleTimeout and MaxHeaderBytes, which
// cannot be disabled (validation refuses negative values).
type HTTPServer struct {
	// ReadHeaderTimeout bounds the TLS handshake and the reading of a
	// request head. Default 10 s.
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	// IdleTimeout closes a keep-alive connection that waits for its next
	// request this long. Default 120 s.
	IdleTimeout time.Duration `yaml:"idle_timeout"`
	// MaxHeaderBytes bounds a request head, for the first request of a
	// connection and for the requests that follow on an HTTP tunnel.
	// Default 64 KiB, at least 4096 and at most 1 MiB.
	MaxHeaderBytes int `yaml:"max_header_bytes"`
	// MaxConns bounds the open connections of the listener. Default 1100.
	MaxConns int `yaml:"max_conns"`
	// MaxConnsPerIP bounds the open connections of one source address
	// (IPv6: one /64). Default 128.
	MaxConnsPerIP int `yaml:"max_conns_per_ip"`
	// FrontendReadTimeout bounds reading the body of a web UI request,
	// counted from the end of its head. It applies until the body has been
	// read; the handler's own work afterwards is not limited by it. Default
	// 15 s. Tunnel requests have none.
	FrontendReadTimeout time.Duration `yaml:"frontend_read_timeout"`
	// FrontendWriteTimeout bounds writing a web UI response. Default 30 s.
	FrontendWriteTimeout time.Duration `yaml:"frontend_write_timeout"`
}

// Resolved returns the settings with the defaults applied; a disabled
// setting is 0. The settings that cannot be disabled take their default for
// any value that is not positive.
func (h HTTPServer) Resolved() HTTPServer {
	if h.ReadHeaderTimeout <= 0 {
		h.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if h.IdleTimeout <= 0 {
		h.IdleTimeout = DefaultIdleTimeout
	}
	if h.MaxHeaderBytes <= 0 {
		h.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	h.MaxConns = resolve(h.MaxConns, DefaultMaxConns)
	h.MaxConnsPerIP = resolve(h.MaxConnsPerIP, DefaultMaxConnsPerIP)
	h.FrontendReadTimeout = resolve(h.FrontendReadTimeout, DefaultFrontendReadTimeout)
	h.FrontendWriteTimeout = resolve(h.FrontendWriteTimeout, DefaultFrontendWriteTimeout)
	return h
}

// DefaultRevalidateInterval is the default of tunnel.revalidate_interval.
const DefaultRevalidateInterval = 30 * time.Second

// minRevalidateInterval keeps a misconfigured interval from turning the
// revalidation query into a load on the database.
const minRevalidateInterval = time.Second

// maxFrameBytes is the protocol ceiling of a control frame.
const maxFrameBytes = 1 << 20

// Tunnel configures the tunnel listener (listen.tunnel_addr) and the client
// sessions on it. Zero selects the default named on the field, negative
// disables.
type Tunnel struct {
	HandshakeTimeout       time.Duration `yaml:"handshake_timeout"`         // accept to HelloAck, 10s
	VerifyTimeout          time.Duration `yaml:"verify_timeout"`            // one token check or reservation lookup, 5s
	MaxUnauthConns         int           `yaml:"max_unauth_conns"`          // 256
	MaxUnauthConnsPerIP    int           `yaml:"max_unauth_conns_per_ip"`   // 16
	MaxPreAuthFrameBytes   int           `yaml:"max_preauth_frame_bytes"`   // 4096, at most 1 MiB
	MaxControlFrameBytes   int           `yaml:"max_control_frame_bytes"`   // 16384, at most 1 MiB
	AcceptBacklog          int           `yaml:"accept_backlog"`            // 32, at most 256
	MaxStreamsPerSession   int           `yaml:"max_streams_per_session"`   // 512
	MaxStreamsPerUser      int           `yaml:"max_streams_per_user"`      // 256, all sessions of one user together
	ControlBurst           int           `yaml:"control_burst"`             // 20
	ControlRefillPerSecond int           `yaml:"control_refill_per_second"` // 5
	MaxSessionsPerUser     int           `yaml:"max_sessions_per_user"`     // 10
	MaxSessions            int           `yaml:"max_sessions"`              // 350
	// RevalidateInterval is how often the server checks the tokens of the
	// open database sessions and closes those whose token was revoked,
	// expired or deleted or whose account was disabled. Default 30 s; at
	// least 1 s; negative disables.
	RevalidateInterval time.Duration `yaml:"revalidate_interval"`
}

// RevalidateEvery returns the revalidation interval with the default
// applied, or 0 when the revalidation is disabled.
func (t Tunnel) RevalidateEvery() time.Duration {
	return resolve(t.RevalidateInterval, DefaultRevalidateInterval)
}

// Edge configures the visitor side of the tunnels. Zero selects the default
// named on the field, negative disables.
type Edge struct {
	// MaxConns bounds the visitor connections of the HTTP and the TCP edge
	// together. Default 1000. The tunnel stream of a connection counts until
	// it is gone from the tunnel session, which is later than the visitor
	// when the tunnel client keeps its side open (up to yamux's close timer,
	// five minutes); the per-tunnel and per-address limits count it the same
	// way, and so do udp.max_flows and its per-port and per-address limits for
	// the streams of flows.
	MaxConns int      `yaml:"max_conns"`
	HTTP     EdgeHTTP `yaml:"http"`
	TCP      EdgeTCP  `yaml:"tcp"`
	UDP      EdgeUDP  `yaml:"udp"`
}

// EdgeHTTP configures the HTTP tunnels. The size of a request head is
// http_server.max_header_bytes.
type EdgeHTTP struct {
	MaxConnsPerTunnel int           `yaml:"max_conns_per_tunnel"` // 256
	MaxConnsPerIP     int           `yaml:"max_conns_per_ip"`     // 64 per tunnel
	IdleTimeout       time.Duration `yaml:"idle_timeout"`         // 5m
}

// EdgeTCP configures the TCP tunnels.
type EdgeTCP struct {
	MaxConnsPerTunnel int           `yaml:"max_conns_per_tunnel"` // 256
	MaxConnsPerIP     int           `yaml:"max_conns_per_ip"`     // 64 per tunnel
	IdleTimeout       time.Duration `yaml:"idle_timeout"`         // 30m
}

// EdgeUDP configures the UDP tunnels. The flow idle timeout and buffer are
// udp.flow_idle_timeout and udp.flow_buffer_size.
type EdgeUDP struct {
	MaxFlowsPerPort       int `yaml:"max_flows_per_port"`        // 256
	MaxFlowsPerIP         int `yaml:"max_flows_per_ip"`          // 64 per port
	MaxFlows              int `yaml:"max_flows"`                 // 768
	ReplyCredit           int `yaml:"reply_credit"`              // 256 replies per inbound datagram
	MaxReplyCredit        int `yaml:"max_reply_credit"`          // 4096
	MaxQueuedBytesPerFlow int `yaml:"max_queued_bytes_per_flow"` // 256 KiB
	MaxQueuedBytesPerPort int `yaml:"max_queued_bytes_per_port"` // 2 MiB
	MaxQueuedBytes        int `yaml:"max_queued_bytes"`          // 64 MiB
}

// Limits configures the accounts. Zero selects the default named on the
// field, negative disables, except UnverifiedAccountTTL.
type Limits struct {
	MaxReservationsPerUser int `yaml:"max_reservations_per_user"` // 10 subdomains
	MaxTokensPerUser       int `yaml:"max_tokens_per_user"`       // 25 active API tokens
	MaxTokenNameLength     int `yaml:"max_token_name_length"`     // 64 characters
	MaxUserAgentBytes      int `yaml:"max_user_agent_bytes"`      // 256
	MinPasswordLength      int `yaml:"min_password_length"`       // 8 characters
	MinAdminPasswordLength int `yaml:"min_admin_password_length"` // 12 characters
	MaxPasswordBytes       int `yaml:"max_password_bytes"`        // 1024
	// HashConcurrency and HashWait bound the password hashing: at most
	// HashConcurrency hashes at a time, a request waits at most HashWait for
	// a slot. Defaults 4 and 5 s.
	HashConcurrency int           `yaml:"hash_concurrency"`
	HashWait        time.Duration `yaml:"hash_wait"`
	// HashPerIP bounds the web requests with password-hash work (login,
	// sign-up, reset, password change, admin re-entry, admin-set password)
	// that one client address (IPv6: one /64) has in flight at the same
	// time; one over it is answered 429 at once. Unset (zero), tunneld uses
	// min(2, max(1, C/2)) for the effective hash_concurrency C (4 -> 2,
	// 3 -> 1, 2 -> 1, 1 -> 1, 8 -> 2; with C = 1 one address can hold the
	// only slot), and 2 when hash_concurrency is switched off. A set
	// positive value must be lower than the effective hash_concurrency.
	HashPerIP int `yaml:"hash_per_ip"`
	// UnverifiedAccountTTL switches on the deletion of accounts that are
	// unverified, not admin, not disabled, older than the TTL and own no
	// token and no reservation. Off unless set (zero and negative: off);
	// a positive value must be at least one hour.
	UnverifiedAccountTTL time.Duration `yaml:"unverified_account_ttl"`
	// PendingAccountTTL is how long an account waits for approval
	// (auth.signup: approval or closed) before it is deleted; admins,
	// disabled accounts and accounts that own a token or a reservation
	// stay. Zero selects 720h, negative switches the deletion off; a
	// positive value must be at least one hour.
	PendingAccountTTL time.Duration `yaml:"pending_account_ttl"`
}

// TCP configures the public TCP tunneling edge. When Enabled is false the
// server refuses register_tcp requests.
type TCP struct {
	Enabled   bool      `yaml:"enabled"`
	PortRange PortRange `yaml:"port_range"`
}

// UDP configures the public UDP tunneling edge. When Enabled is false the
// server refuses register_udp requests.
type UDP struct {
	Enabled   bool      `yaml:"enabled"`
	PortRange PortRange `yaml:"port_range"`
	// FlowIdleTimeout closes a flow that has received nothing for this
	// long. Zero selects 30 s; it cannot be disabled.
	FlowIdleTimeout time.Duration `yaml:"flow_idle_timeout"`
	// FlowBufferSize is the number of datagrams a flow buffers. Zero
	// selects 64; at most 256.
	FlowBufferSize int `yaml:"flow_buffer_size"`
}

// PortRange is an inclusive [Low, High] port range. Ranges start at 1024 or
// above and must not contain the ports the server listens on itself.
type PortRange struct {
	Low  int `yaml:"low"`
	High int `yaml:"high"`
}

// Listen holds the server bind addresses.
type Listen struct {
	TunnelAddr string `yaml:"tunnel_addr"` // e.g. ":7443"
	HTTPAddr   string `yaml:"http_addr"`   // e.g. ":443"
}

// TLS describes how to source the TLS certificate.
// Exactly one of the three sources must be configured:
//   - CertFile+KeyFile: static PEM files on disk.
//   - SelfSignedHosts: in-memory dev cert.
//   - ACME: Let's Encrypt via DNS-01.
type TLS struct {
	CertFile        string   `yaml:"cert_file,omitempty"`
	KeyFile         string   `yaml:"key_file,omitempty"`
	SelfSignedHosts []string `yaml:"self_signed_hosts,omitempty"`
	ACME            *ACME    `yaml:"acme,omitempty"`
}

// ACME configures Let's Encrypt DNS-01 via the configured DNS provider.
// The provider reads its credentials from environment variables (e.g. the
// IONOS provider expects IONOS_API_KEY).
type ACME struct {
	Email       string   `yaml:"email"`
	DNSProvider string   `yaml:"dns_provider"` // currently "ionos"
	Domains     []string `yaml:"domains"`      // e.g. ["example.org", "*.example.org"]
	CacheDir    string   `yaml:"cache_dir"`    // e.g. "/var/lib/tunneld/certs"
	Staging     bool     `yaml:"staging"`
}

// supportedDNSProviders are the values tls.acme.dns_provider takes.
var supportedDNSProviders = map[string]bool{"ionos": true}

// supportedSignupModes are the values auth.signup takes.
var supportedSignupModes = map[string]bool{"open": true, "approval": true, "closed": true}

// Auth holds the static tokens (dev-only), and, when database.url is
// configured, the CSRF signing key used by the HTMX frontend and the sign-up
// mode.
type Auth struct {
	// Tokens are static tunnel tokens of at least 16 characters each.
	Tokens  []string `yaml:"tokens,omitempty"`
	CSRFKey string   `yaml:"csrf_key,omitempty"` // base64, 32 bytes decoded
	// Signup is how new accounts start: "open" (the default), "approval"
	// (they wait until an admin approves them) or "closed" (no sign-up;
	// only an admin creates accounts). Database mode only.
	Signup string `yaml:"signup,omitempty"`
}

// SignupMode returns auth.signup: "open", "approval" or "closed"; unset is
// "open".
func (a Auth) SignupMode() string {
	if a.Signup == "" {
		return "open"
	}
	return a.Signup
}

// Database configures the Postgres connection.
type Database struct {
	URL string `yaml:"url"` // e.g. "postgres://user:pass@host:port/db?sslmode=disable"
}

// currentGOOS is runtime.GOOS; tests replace it.
var currentGOOS = runtime.GOOS

// Load reads and validates a YAML config file. Problems that do not stop the
// server are returned in Config.Warnings.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := parse(raw)
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(path); err == nil {
		if w := fileModeWarning(currentGOOS, path, info.Mode()); w != "" {
			cfg.Warnings = append([]string{w}, cfg.Warnings...)
		}
	}
	cfg.Path = path
	if abs, err := filepath.Abs(path); err == nil {
		cfg.Path = abs
	}
	return cfg, nil
}

// parse decodes one YAML document strictly and validates it.
func parse(raw []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		// Not wrapped: the decoder's text quotes the offending value, which
		// can be a secret written under the wrong key.
		return nil, fmt.Errorf("parse config: %s", redactDecodeError(err))
	}
	var next yaml.Node
	if err := dec.Decode(&next); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse config: the file holds more than one YAML document")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.Warnings = cfg.startupWarnings()
	return &cfg, nil
}

// quotedValueRE matches a value yaml.v3 quotes in an error, as in
// "cannot unmarshal !!str `secret` into int": everything from the first to the
// last backtick, across line breaks, so that a value with backticks or line
// breaks of its own goes as a whole. It is applied to one error at a time.
var quotedValueRE = regexp.MustCompile("(?s)`.*`")

// unknownAnchorRE matches the alias name yaml.v3 quotes when an unquoted
// value starting with "*" names no anchor ("unknown anchor 'NAME' referenced").
var unknownAnchorRE = regexp.MustCompile("(?s)unknown anchor '.*' referenced")

// redactDecodeError returns the decoder's error text without the values it
// quotes; the line numbers, the expected types and unknown key names stay.
// Each error of a *yaml.TypeError is redacted on its own, so that one cannot
// swallow the next.
func redactDecodeError(err error) string {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		parts := make([]string, len(te.Errors))
		for i, e := range te.Errors {
			parts[i] = redactValue(e)
		}
		return "yaml: unmarshal errors:\n  " + strings.Join(parts, "\n  ")
	}
	return redactValue(err.Error())
}

// redactValue removes a quoted value and an unknown alias name from one
// error text.
func redactValue(msg string) string {
	msg = quotedValueRE.ReplaceAllString(msg, "(value not shown)")
	return unknownAnchorRE.ReplaceAllString(msg, "unknown anchor (name not shown) referenced")
}

// resolve applies the convention of the limits: zero selects def, a
// negative value disables (0).
func resolve[T int | time.Duration](v, def T) T {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return v
}

// CSRFKeyBytes decodes the configured auth.csrf_key. Callers must have
// already validated the config via Load.
func (c *Config) CSRFKeyBytes() []byte {
	b, _ := base64.StdEncoding.DecodeString(c.Auth.CSRFKey)
	return b
}
