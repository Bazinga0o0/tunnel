package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/acme"
	"github.com/Bazinga0o0/tunnel/internal/server/audit"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/db"
	"github.com/Bazinga0o0/tunnel/internal/server/edgehttp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeudp"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	"github.com/Bazinga0o0/tunnel/internal/server/passwordreset"
	"github.com/Bazinga0o0/tunnel/internal/server/reaper"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/services"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
	"github.com/Bazinga0o0/tunnel/internal/server/verifications"
)

// setHashLimits is auth.SetHashLimits; tests record the call.
var setHashLimits = auth.SetHashLimits

// newFrontend is frontend.New; tests wrap the handler.
var newFrontend = func(opts frontend.Options) http.Handler { return frontend.New(opts) }

// app is the assembled server: TLS, services and handlers, built from the
// config but not yet listening. serve runs it; tests build it in-process.
type app struct {
	cfg    *config.Config
	logger *slog.Logger

	tlsConfig *tls.Config
	acme      *acme.Manager // nil unless tls.acme

	reg      *registry.Registry
	acceptor *acceptor.Acceptor
	frontend http.Handler // nil in static-token mode
	public   *http.Server // the dispatcher of the public listener

	// Database mode only.
	pool         *pgxpool.Pool
	users        *users.Service
	tokens       *tokens.Service
	reservations *reservations.Service
	sessions     *sessions.Service
	reaper       *reaper.Reaper
	revalidator  *sessionRevalidator     // nil when tunnel.revalidate_interval is negative
	services     map[string]http.Handler // the proxies of the registered services by host
	serviceAPI   http.Handler            // nil without services or service_api.addr
	directory    *frontend.Directory     // the listed services; nil without services; reload replaces its content

	tcpPool *edgetcp.Pool // nil unless tcp.enabled; reload changes its excluded ports

	reloadMu sync.Mutex
	current  *config.Config // the config the server runs with, as far as reload changed it
}

// newApp builds the server. With ACME and no usable certificate it waits
// until one is obtained or ctx ends. On error everything it opened is
// closed again.
func newApp(ctx context.Context, cfg *config.Config, logger *slog.Logger) (a *app, err error) {
	a = &app{cfg: cfg, current: cfg, logger: logger, reg: registry.New()}
	defer func() {
		if err != nil {
			a.closePool()
		}
	}()

	setHashLimits(hashLimits(cfg))

	a.tlsConfig, a.acme, err = buildTLSConfig(ctx, cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}

	accOpts := acceptorOptions(cfg)
	accOpts.Registry = a.reg
	accOpts.Logger = logger

	if cfg.Database.URL != "" {
		if err := a.openDatabase(ctx, &accOpts); err != nil {
			return nil, err
		}
	} else {
		verifier, err := auth.NewStaticTokenVerifier(cfg.Auth.Tokens)
		if err != nil {
			return nil, fmt.Errorf("auth.tokens: %w", err)
		}
		accOpts.Verifier = verifier
		logger.Info("static-token auth enabled", "tokens", len(cfg.Auth.Tokens))
	}

	// One total for the visitor connections of the HTTP and the TCP edge.
	budget := edgeBudget(cfg)
	if cfg.TCP.Enabled {
		tcpOpts := edgeTCPOptions(cfg, logger, budget)
		a.tcpPool = tcpOpts.Pool
		accOpts.TCPEdge = edgetcp.NewWithOptions(tcpOpts)
		logger.Info("tcp edge enabled", "low", cfg.TCP.PortRange.Low, "high", cfg.TCP.PortRange.High)
	}
	if cfg.UDP.Enabled {
		accOpts.UDPEdge = edgeudp.New(edgeUDPOptions(cfg, logger))
		logger.Info("udp edge enabled", "low", cfg.UDP.PortRange.Low, "high", cfg.UDP.PortRange.High)
	}

	a.acceptor = acceptor.New(accOpts)
	edge := edgehttp.New(edgeHTTPOptions(cfg, a.reg, logger, budget))
	a.public = newPublicServer(dispatchHost(cfg.Domain, a.frontend, edge, a.services, cfg.HTTPServer), cfg.HTTPServer, logger)
	return a, nil
}

// openDatabase connects, migrates and builds the services, the web UI, the
// reaper and the session revalidation.
func (a *app) openDatabase(ctx context.Context, accOpts *acceptor.Options) error {
	cfg, logger := a.cfg, a.logger
	pool, err := db.Open(ctx, cfg.Database.URL)
	if err != nil {
		return fmt.Errorf("db open: %w", err)
	}
	a.pool = pool
	if err := db.MigrateUp(ctx, pool); err != nil {
		return fmt.Errorf("db migrate: %w", err)
	}
	a.users = users.NewServiceWithOptions(pool, userOptions(cfg))
	// It runs before the listeners start, so no tunnel login sees an admin
	// or a token owner as waiting.
	if _, err := approveExistingIfRequired(ctx, cfg, a.users, logger); err != nil {
		return err
	}
	a.tokens = tokens.NewServiceWithOptions(pool, tokenOptions(cfg))
	a.reservations = reservations.NewServiceWithOptions(pool, reservationOptions(cfg))
	a.sessions = sessions.NewServiceWithOptions(pool, sessionOptions(cfg))
	verSvc := verifications.NewService(pool, a.users)
	resetSvc := passwordreset.NewService(pool, a.users, a.sessions)

	verifier := auth.NewDBVerifier(a.tokens)
	accOpts.DBVerifier = verifier
	accOpts.Reservations = a.reservations
	auditSvc := audit.NewService(pool)
	if err := a.openServices(ctx, verifier, auditSvc); err != nil {
		return err
	}

	var mailer mail.Mailer
	if cfg.Mail.SMTP.Host != "" {
		mailer = mail.NewSMTPMailer(smtpConfig(cfg))
		logger.Info("smtp mailer enabled", "host", cfg.Mail.SMTP.Host, "port", cfg.Mail.SMTP.Port,
			"allow_plaintext", cfg.Mail.SMTP.AllowPlaintext)
	} else {
		logger.Info("smtp mailer disabled (mail.smtp.host empty)")
	}

	opts := frontendOptions(cfg)
	opts.Users = a.users
	opts.Tokens = a.tokens
	opts.Reservations = a.reservations
	opts.Sessions = a.sessions
	opts.Registry = a.reg
	if len(cfg.Services) > 0 {
		a.directory = &frontend.Directory{}
		a.directory.Set(directoryEntries(cfg))
		opts.Directory = a.directory
		opts.DirectoryVerifier = verifier
	}
	opts.Audit = auditSvc
	opts.Mailer = mailer
	opts.Verifications = verSvc
	opts.PasswordReset = resetSvc
	a.frontend = newFrontend(opts)
	logger.Info("db-backed auth enabled", "db", "postgres", "frontend", "enabled", "audit", "enabled")

	a.reaper = reaper.NewWithOptions(pool, reaperOptions(cfg, logger))
	if every := cfg.Tunnel.RevalidateEvery(); every > 0 {
		a.revalidator = newSessionRevalidator(a.reg, a.tokens, every, logger)
	}
	return nil
}

// approveExistingIfRequired approves, in approval and closed mode
// (approvalRequired), the accounts that are in use already: admins and every
// account that holds an API token or a reservation (users.ApproveExisting).
// Accounts that are in use thus keep working when a server switches to such
// a mode. The server calls it at every start, the admin CLI before every
// command that changes state. It returns the number of accounts it
// approved and logs it on logger, unless logger is nil. In open mode it
// does nothing.
func approveExistingIfRequired(ctx context.Context, cfg *config.Config, userSvc *users.Service, logger *slog.Logger) (int64, error) {
	if !approvalRequired(cfg) {
		return 0, nil
	}
	n, err := userSvc.ApproveExisting(ctx)
	if err != nil {
		return 0, fmt.Errorf("signup approval: approve existing accounts: %w", err)
	}
	if logger != nil {
		logger.Info("signup approval: existing accounts approved", "count", n)
	}
	return n, nil
}

// openServices builds the proxies of the registered services and keeps
// their subdomains from tunnels and reservations. A subdomain an account
// reserved before it became a service's is only worth a warning: the service
// takes its requests all the same (dispatchHost asks the services before the
// tunnels). A reservation of a service port is warned about as well: its
// account may host on the port until the service sets another holder. It
// reads the service secrets and, with service_api.addr, builds the service
// API; runServer binds it.
func (a *app) openServices(ctx context.Context, verifier services.Verifier, auditor services.Auditor) error {
	cfg, logger := a.cfg, a.logger
	if len(cfg.Services) == 0 {
		return nil
	}
	apiServices, err := serviceAPIServices(cfg)
	if err != nil {
		return err
	}
	if cfg.ServiceAPI.Addr != "" {
		a.serviceAPI = services.NewAPI(apiServices, a.reservations, a.users, approvalRequired(cfg), a.reg, auditor, logger)
	}
	proxies, err := serviceProxies(cfg, verifier, a.users, logger)
	if err != nil {
		return err
	}
	a.services = proxies
	for _, s := range cfg.Services {
		reservations.AddSystemReserved(s.Subdomain)
		owner, reserved, err := a.reservations.Owner(ctx, s.Subdomain)
		switch {
		case err != nil:
			logger.Warn("service subdomain: cannot check for an older reservation",
				"service", s.Name, "subdomain", s.Subdomain, "err", err)
		case reserved:
			logger.Warn("service subdomain is reserved by an account; its requests go to the service, "+
				"not to that account's tunnels. Release it with tunneld admin release-subdomain --config "+
				configArg(cfg.Path)+" --subdomain "+s.Subdomain,
				"service", s.Name, "subdomain", s.Subdomain, "user_id", owner)
		}
		a.warnAboutReservedServicePorts(ctx, s)
		logger.Info("service enabled", "service", s.Name, "subdomain", s.Subdomain, "upstream", s.Upstream,
			"tcp_ports", s.TCPPorts)
	}
	return nil
}

// warnAboutReservedServicePorts logs a warning for every tcp_ports entry of
// s that is reserved. The holder of a service port is such a reservation:
// its account may open a tunnel on the port until the service sets another
// holder or clears it. One the service set is as it should be; one granted in
// the admin panel before the port became the service's, or after, gives an
// account the port behind the service's back. The server cannot tell the
// two apart, so it names the account and the ways to remove it.
func (a *app) warnAboutReservedServicePorts(ctx context.Context, s config.Service) {
	for _, port := range s.TCPPorts {
		owner, reserved, err := a.reservations.OwnerTCPPort(ctx, port)
		switch {
		case err != nil:
			a.logger.Warn("service port: cannot check for a reservation",
				"service", s.Name, "port", port, "err", err)
		case reserved:
			a.logger.Warn(fmt.Sprintf("service port is reserved by an account, which may host on it until the "+
				"service sets another holder or clears it. If the service did not set this holder, remove it: "+
				"DELETE /v1/tcp-ports/%d/holder on the service API, or in the admin panel (Reservations)", port),
				"service", s.Name, "port", port, "user_id", owner)
		}
	}
}

// configArg is the config file as the --config argument of a command the
// server suggests in its log: the path it was loaded from, quoted for a
// POSIX shell where needed, or the placeholder PATH when it is not known.
func configArg(path string) string {
	if path == "" {
		return "PATH"
	}
	return shellWord(path)
}

// shellWord returns s as one word for a POSIX shell: unchanged when it has
// only characters no shell treats specially, otherwise in single quotes.
func shellWord(s string) string {
	plain := s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+:,=@%", r))
	}) < 0
	if plain {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// startBackground starts the loops that run beside the listeners: ACME
// renewal, reaper, session revalidation. They end with ctx.
func (a *app) startBackground(ctx context.Context) {
	if a.acme != nil {
		go a.acme.RenewalLoop(ctx)
	}
	if a.reaper != nil {
		go a.reaper.Run(ctx)
		a.logger.Info("reaper started", "interval", reaper.DefaultInterval,
			"unverified_account_ttl", a.cfg.Limits.UnverifiedAccountTTL.String(),
			"pending_account_ttl", pendingAccountTTL(a.cfg).String())
	}
	switch {
	case a.revalidator != nil:
		go a.revalidator.run(ctx)
		a.logger.Info("tunnel session revalidation started", "interval", a.revalidator.interval)
	case a.pool != nil:
		a.logger.Warn("tunnel session revalidation disabled (tunnel.revalidate_interval is negative): " +
			"revoking a token or disabling an account in the admin CLI leaves open tunnels connected")
	}
}

// closeFrontend stops the web UI's mail sender: it delivers what is queued
// until timeout. The deadline is its own: a context that has ended already
// would make Close give up although the queue is idle.
func (a *app) closeFrontend(timeout time.Duration) error {
	c, ok := a.frontend.(interface{ Close(context.Context) error })
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.Close(ctx)
}

// closePool closes the database pool, if there is one.
func (a *app) closePool() {
	if a.pool != nil {
		a.pool.Close()
	}
}
