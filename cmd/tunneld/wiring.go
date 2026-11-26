package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
	"github.com/Bazinga0o0/tunnel/internal/server/edgehttp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeudp"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	"github.com/Bazinga0o0/tunnel/internal/server/reaper"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/services"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// The functions below translate the config into the options of the server's
// packages. The config keeps the operator's values as written: zero selects
// the package's default and a negative value disables the limit, which is the
// convention of every one of these options.

// udpSweepInterval is how often the UDP edge looks for idle flows.
const udpSweepInterval = 5 * time.Second

// acceptorOptions returns the tunnel listener's options without the
// registry, the verifier and the edges.
func acceptorOptions(cfg *config.Config) acceptor.Options {
	t := cfg.Tunnel
	return acceptor.Options{
		Domain:                 cfg.Domain,
		ServerVersion:          version,
		HandshakeTimeout:       t.HandshakeTimeout,
		VerifyTimeout:          t.VerifyTimeout,
		MaxUnauthConns:         t.MaxUnauthConns,
		MaxUnauthConnsPerIP:    t.MaxUnauthConnsPerIP,
		MaxPreAuthFrameSize:    t.MaxPreAuthFrameBytes,
		MaxControlFrameSize:    t.MaxControlFrameBytes,
		AcceptBacklog:          t.AcceptBacklog,
		MaxStreamsPerSession:   t.MaxStreamsPerSession,
		MaxStreamsPerUser:      t.MaxStreamsPerUser,
		ControlBurst:           t.ControlBurst,
		ControlRefillPerSecond: t.ControlRefillPerSecond,
		MaxSessionsPerUser:     t.MaxSessionsPerUser,
		MaxSessions:            t.MaxSessions,
	}
}

// edgeBudget returns the total that the HTTP and the TCP edge share
// (edge.max_conns), or nil when the operator disabled it.
func edgeBudget(cfg *config.Config) *edgeguard.Budget {
	switch max := cfg.Edge.MaxConns; {
	case max < 0:
		return nil
	case max == 0:
		return edgeguard.NewBudget(edgetcp.DefaultMaxConns)
	default:
		return edgeguard.NewBudget(max)
	}
}

// edgeHTTPOptions returns the options of the HTTP tunnel edge. Its request
// head limit is the public server's (http_server.max_header_bytes): the
// server bounds the first request of a connection, the edge the ones after.
func edgeHTTPOptions(cfg *config.Config, reg *registry.Registry, logger *slog.Logger, budget *edgeguard.Budget) edgehttp.Options {
	e := cfg.Edge
	return edgehttp.Options{
		Domain:            cfg.Domain,
		Registry:          reg,
		Logger:            logger,
		MaxConnsPerTunnel: e.HTTP.MaxConnsPerTunnel,
		MaxConnsPerIP:     e.HTTP.MaxConnsPerIP,
		MaxConns:          e.MaxConns,
		TotalBudget:       budget,
		IdleTimeout:       e.HTTP.IdleTimeout,
		MaxHeaderBytes:    cfg.HTTPServer.MaxHeaderBytes,
	}
}

// edgeTCPOptions returns the options of the TCP tunnel edge; tcp.enabled
// must be set (the port range is validated then). The ports of the
// registered services are kept out of the pool's random draw.
func edgeTCPOptions(cfg *config.Config, logger *slog.Logger, budget *edgeguard.Budget) edgetcp.Options {
	e := cfg.Edge
	pool := edgetcp.NewPool(cfg.TCP.PortRange.Low, cfg.TCP.PortRange.High)
	pool.Exclude(serviceTCPPorts(cfg))
	return edgetcp.Options{
		Pool:              pool,
		Logger:            logger,
		MaxConnsPerTunnel: e.TCP.MaxConnsPerTunnel,
		MaxConnsPerIP:     e.TCP.MaxConnsPerIP,
		MaxConns:          e.MaxConns,
		TotalBudget:       budget,
		IdleTimeout:       e.TCP.IdleTimeout,
	}
}

// edgeUDPOptions returns the options of the UDP tunnel edge; udp.enabled
// must be set.
func edgeUDPOptions(cfg *config.Config, logger *slog.Logger) edgeudp.Options {
	u := cfg.Edge.UDP
	return edgeudp.Options{
		Pool:                  edgeudp.NewPool(cfg.UDP.PortRange.Low, cfg.UDP.PortRange.High),
		IdleTimeout:           cfg.UDP.FlowIdleTimeout,
		BufferSize:            cfg.UDP.FlowBufferSize,
		SweepInterval:         udpSweepInterval,
		Logger:                logger,
		MaxFlowsPerPort:       u.MaxFlowsPerPort,
		MaxFlowsPerIP:         u.MaxFlowsPerIP,
		MaxFlows:              u.MaxFlows,
		ReplyCredit:           u.ReplyCredit,
		MaxReplyCredit:        u.MaxReplyCredit,
		MaxQueuedBytesPerFlow: u.MaxQueuedBytesPerFlow,
		MaxQueuedBytesPerPort: u.MaxQueuedBytesPerPort,
		MaxQueuedBytes:        u.MaxQueuedBytes,
	}
}

// serviceProxies returns the proxies of the registered services, keyed by
// their host <subdomain>.<domain> as dispatchHost expects. A zero
// max_request_body_bytes selects services.DefaultMaxRequestBodyBytes in
// NewProxy.
func serviceProxies(cfg *config.Config, v services.Verifier, emails services.EmailLookup, logger *slog.Logger) (map[string]http.Handler, error) {
	proxies := make(map[string]http.Handler, len(cfg.Services))
	for _, s := range cfg.Services {
		h, err := services.NewProxy(s, v, emails, logger)
		if err != nil {
			return nil, fmt.Errorf("services: %w", err)
		}
		proxies[s.Subdomain+"."+cfg.Domain] = h
	}
	return proxies, nil
}

// directoryEntries returns the services of cfg that are listed in the
// directory, in config order, with their public URL.
func directoryEntries(cfg *config.Config) []frontend.DirectoryEntry {
	apex, ok := edgehttp.NormalizeHost(cfg.Domain)
	if !ok {
		apex = strings.ToLower(cfg.Domain)
	}
	out := []frontend.DirectoryEntry{}
	for _, s := range cfg.Services {
		if !s.Directory.Listed {
			continue
		}
		out = append(out, frontend.DirectoryEntry{
			Name:        s.Name,
			Title:       s.Directory.Title,
			Description: s.Directory.Description,
			URL:         "https://" + s.Subdomain + "." + apex,
		})
	}
	return out
}

// serviceTCPPorts returns the tcp_ports of every registered service.
func serviceTCPPorts(cfg *config.Config) []int {
	var ports []int
	for _, s := range cfg.Services {
		ports = append(ports, s.TCPPorts...)
	}
	return ports
}

// minServiceSecretLength is the length a service secret needs at least, in
// characters.
const minServiceSecretLength = 32

// serviceAPIServices reads the secrets of the registered services and
// returns the services as the service API knows them. A secret that cannot
// be read, is shorter than minServiceSecretLength or is another service's
// as well ends the start: the API would let no service in, or the wrong one.
func serviceAPIServices(cfg *config.Config) ([]services.APIService, error) {
	out := make([]services.APIService, 0, len(cfg.Services))
	for _, s := range cfg.Services {
		secret, err := readServiceSecret(s)
		if err != nil {
			return nil, err
		}
		for _, other := range out {
			if bytes.Equal(other.Secret, secret) {
				return nil, fmt.Errorf("services: %q and %q have the same secret; each service needs its own", other.Name, s.Name)
			}
		}
		ports := make(map[int]bool, len(s.TCPPorts))
		for _, p := range s.TCPPorts {
			ports[p] = true
		}
		out = append(out, services.APIService{Name: s.Name, Secret: secret, Ports: ports})
	}
	return out, nil
}

// readServiceSecret reads the secret of s from its secret_file. White space
// around it, such as the newline that "openssl rand -hex 32 > file" leaves,
// is not part of it. The errors never quote the file's content.
func readServiceSecret(s config.Service) ([]byte, error) {
	raw, err := os.ReadFile(s.SecretFile)
	if err != nil {
		return nil, fmt.Errorf("services: %q: secret_file: %w", s.Name, err)
	}
	secret := bytes.TrimSpace(raw)
	if utf8.RuneCount(secret) < minServiceSecretLength {
		return nil, fmt.Errorf("services: %q: the secret in %s must have at least %d characters "+
			"(generate one with: openssl rand -hex 32)", s.Name, s.SecretFile, minServiceSecretLength)
	}
	return secret, nil
}

// smtpConfig returns the SMTP transport of mail.smtp. The server and the
// admin CLI's send-test-email build their mailer from it.
func smtpConfig(cfg *config.Config) mail.SMTPConfig {
	s := cfg.Mail.SMTP
	return mail.SMTPConfig{
		Host:           s.Host,
		Port:           s.Port,
		Username:       s.Username,
		Password:       s.Password,
		From:           cfg.Mail.From,
		AuthRequired:   s.AuthRequired,
		AllowPlaintext: s.AllowPlaintext,
		DialTimeout:    s.DialTimeout,
		SendTimeout:    s.SendTimeout,
	}
}

func hashLimits(cfg *config.Config) auth.HashLimits {
	return auth.HashLimits{MaxConcurrent: cfg.Limits.HashConcurrency, MaxWait: cfg.Limits.HashWait}
}

func userOptions(cfg *config.Config) users.Options {
	l := cfg.Limits
	return users.Options{
		MinPasswordLength:      l.MinPasswordLength,
		MinAdminPasswordLength: l.MinAdminPasswordLength,
		MaxPasswordBytes:       l.MaxPasswordBytes,
	}
}

func tokenOptions(cfg *config.Config) tokens.Options {
	return tokens.Options{
		MaxActivePerUser: cfg.Limits.MaxTokensPerUser,
		MaxNameLength:    cfg.Limits.MaxTokenNameLength,
		RequireApproved:  approvalRequired(cfg),
	}
}

// approvalRequired reports whether accounts need an admin's approval before
// they can use tokens, reservations and tunnels: auth.signup approval or
// closed. Closing the sign-up does not approve the accounts that wait.
func approvalRequired(cfg *config.Config) bool {
	return cfg.Auth.SignupMode() != "open"
}

func reservationOptions(cfg *config.Config) reservations.Options {
	return reservations.Options{MaxSubdomainsPerUser: cfg.Limits.MaxReservationsPerUser}
}

func sessionOptions(cfg *config.Config) sessions.Options {
	return sessions.Options{MaxUserAgentBytes: cfg.Limits.MaxUserAgentBytes}
}

func reaperOptions(cfg *config.Config, logger *slog.Logger) reaper.Options {
	return reaper.Options{
		UnverifiedAccountTTL: cfg.Limits.UnverifiedAccountTTL,
		PendingAccountTTL:    pendingAccountTTL(cfg),
		Logger:               logger,
	}
}

// pendingAccountTTL returns the age from which the reaper deletes accounts
// that wait for approval: limits.pending_account_ttl, 720h when it is not
// set, 0 (off) when it is negative. Only in approval and closed mode
// (approvalRequired); with an open sign-up no account waits (the accounts
// simply have no approval), so the rule is off there.
func pendingAccountTTL(cfg *config.Config) time.Duration {
	if !approvalRequired(cfg) {
		return 0
	}
	switch ttl := cfg.Limits.PendingAccountTTL; {
	case ttl == 0:
		return reaper.DefaultPendingAccountTTL
	case ttl < 0:
		return 0
	default:
		return ttl
	}
}

// frontendOptions returns the web UI's options that come from the config:
// everything but the services, the registry, the audit service and the
// mailer, which serve fills in. limits.hash_per_ip is a web UI option too:
// the per-address bound sits in front of the web paths that hash.
func frontendOptions(cfg *config.Config) frontend.Options {
	f := cfg.Frontend
	tcpRange, udpRange := frontendPortRanges(cfg)
	return frontend.Options{
		Domain:                  cfg.Domain,
		TCPPortRange:            tcpRange,
		UDPPortRange:            udpRange,
		CSRFKey:                 cfg.CSRFKeyBytes(),
		CSRFSecure:              true,
		PublicBaseURL:           f.PublicBaseURL,
		LoginFailuresPerAccount: f.LoginFailuresPerAccount,
		LoginFailuresPerIP:      f.LoginFailuresPerIP,
		LoginFailureWindow:      f.LoginFailureWindow,
		LoginsPerAccount:        f.LoginsPerAccount,
		SignupsPerIP:            f.SignupsPerIP,
		SignupWindow:            f.SignupWindow,
		ResetRequestsPerIP:      f.ResetRequestsPerIP,
		ResetRequestsPerAccount: f.ResetRequestsPerAccount,
		ResetRequestWindow:      f.ResetRequestWindow,
		RateLimitMaxKeys:        f.RateLimitMaxKeys,
		MaxRequestBodyBytes:     f.MaxRequestBodyBytes,
		UserActionsPerHour:      f.UserActionsPerHour,
		MailQueueSize:           cfg.Mail.QueueSize,
		HashPerIP:               hashPerIP(cfg.Limits),

		UnauthenticatedAuditRowsPerMinute: f.UnauthenticatedAuditRowsPerMinute,
		SignupMode:                        cfg.Auth.SignupMode(),
	}
}

// hashPerIP returns the per-address bound of the web UI's hash work
// (frontend.Options.HashPerIP). A set limits.hash_per_ip is passed on (the
// config refuses a positive one that is not lower than the effective
// hash_concurrency; a negative one switches the bound off). Unset, the bound
// follows the effective process-wide limit C of limits.hash_concurrency:
// min(2, max(1, C/2)), so that one client address holds at most half of the
// slots, and a lowered C does not hand one address every slot (with C = 1
// it holds the only one). Without a process-wide limit (hash_concurrency
// negative) the frontend's own default applies. It is worked out here
// because only the wiring knows both settings and both packages' defaults.
func hashPerIP(l config.Limits) int {
	if l.HashPerIP != 0 {
		return l.HashPerIP
	}
	c := l.HashConcurrency
	if c == 0 {
		c = auth.DefaultHashConcurrency
	}
	if c < 0 {
		return 0
	}
	return min(frontend.DefaultHashPerIP, max(1, c/2))
}

// frontendPortRanges returns the port ranges the admin panel checks grants
// against: the ranges of the enabled edges, and "not configured" for an edge
// that is off.
func frontendPortRanges(cfg *config.Config) (tcp, udp frontend.PortRange) {
	if cfg.TCP.Enabled {
		tcp = frontend.PortRange{Low: cfg.TCP.PortRange.Low, High: cfg.TCP.PortRange.High}
	}
	if cfg.UDP.Enabled {
		udp = frontend.PortRange{Low: cfg.UDP.PortRange.Low, High: cfg.UDP.PortRange.High}
	}
	return tcp, udp
}
