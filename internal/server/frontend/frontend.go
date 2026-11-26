// Package frontend serves the self-service HTMX web UI on app.<domain>.
package frontend

import (
	"context"
	"crypto/rand"
	"embed"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"

	"github.com/Bazinga0o0/tunnel/internal/server/audit"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend/templates"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	"github.com/Bazinga0o0/tunnel/internal/server/passwordreset"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
	"github.com/Bazinga0o0/tunnel/internal/server/verifications"
)

//go:embed web/static/*
var staticFS embed.FS

// Options configures the frontend handler.
type Options struct {
	Domain       string
	Users        *users.Service
	Tokens       *tokens.Service
	Reservations *reservations.Service
	Sessions     *sessions.Service
	// Registry is the live session registry. The /tunnels page and the admin
	// connections page read it; it is also used to close sessions: a user's
	// revoked token (KillByToken), a reserved name (EvictSubdomain), and the
	// admin actions disable, revoke-all-tokens, grant (Evict…) and kill.
	// nil: no live data, nothing is closed.
	Registry *registry.Registry

	// TCPPortRange and UDPPortRange are the port ranges of the TCP and UDP
	// edges. The admin panel refuses to grant a port outside the range. The
	// zero value means "not configured": any port from 1 to 65535 can be
	// granted.
	TCPPortRange PortRange
	UDPPortRange PortRange

	// Audit records security-relevant actions in the audit log; handlers
	// write to it through Options.audit (audit.go). nil disables audit
	// logging.
	Audit *audit.Service

	// CSRFKey is the 32-byte key used by gorilla/csrf to sign its tokens.
	// If empty, a random in-memory key is generated (a warning is logged —
	// this is intended for tests only; production must pass a real key).
	CSRFKey []byte
	// CSRFSecure toggles the Secure attribute on the CSRF cookie. Production
	// must be true (HTTPS only). Set to false only in tests using httptest.
	// It also selects the cookie names: __Host-tunneld_session and
	// __Host-tunneld_csrf when true, tunneld_session and _gorilla_csrf when
	// false.
	CSRFSecure bool

	// Mailer dispatches transactional email. nil disables email sending
	// (dev / tests that don't care about email).
	Mailer mail.Mailer
	// Verifications issues email-verification tokens. nil disables the
	// verification email path on signup.
	Verifications *verifications.Service
	// PasswordReset issues password-reset tokens. nil disables the
	// forgot-password flow.
	PasswordReset *passwordreset.Service
	// PublicBaseURL is the user-facing base URL (e.g. "https://app.example.org")
	// used when composing links in transactional emails. When empty, email
	// dispatch is skipped.
	PublicBaseURL string

	// Rate limits and request bounds. For the counts and sizes below a zero
	// value selects the default and a negative value disables the limit. A
	// window of zero or less selects the default window.
	//
	// The limits count per client: the IP address of the connection's peer,
	// with IPv6 addresses grouped by /64. Account limits count per email
	// address as typed (trimmed, lower-cased), whether or not an account
	// with that address exists. Every check runs before a password is
	// hashed; over a limit the handler answers 429 with Retry-After.

	// LoginFailuresPerAccount is the number of failed logins for one email
	// address within LoginFailureWindow. Default 10. An address over the
	// limit refuses even the correct password until its oldest counted
	// failure has left the window: anybody who knows an address can keep
	// that account locked out of the web UI by sending wrong passwords (API
	// tokens and running tunnels are not affected). A negative value
	// disables the per-account limit; the per-client limit still applies.
	LoginFailuresPerAccount int
	// LoginFailuresPerIP is the number of failed logins from one client
	// within LoginFailureWindow. Default 30.
	LoginFailuresPerIP int
	// LoginFailureWindow is the window of the two login limits and of
	// LoginsPerAccount. Default 15 minutes.
	LoginFailureWindow time.Duration
	// LoginsPerAccount is the number of successful logins for one email
	// address (trimmed, lower-cased) within LoginFailureWindow. It bounds
	// how fast one account can create sessions and audit rows. Only a login
	// whose password matched and whose session was stored counts; wrong
	// passwords, unknown addresses and logins the server could not decide
	// do not, so it is no lever to keep somebody else's account out. Once
	// the address has reached it, every login of the address is answered
	// 429 before the password is hashed, until the window has passed (which
	// shows that the address has an account at its limit). The check before
	// the hash counts nothing; the login is recorded after the password
	// matched and before the session is created, and refused with the same
	// 429 when the limit has been reached meanwhile, so the bound is exact.
	// Default 30.
	LoginsPerAccount int
	// SignupsPerIP is the number of sign-up attempts from one client within
	// SignupWindow. Only attempts with a valid address and password count.
	// Default 5.
	SignupsPerIP int
	// SignupWindow is the window of SignupsPerIP. Default 1 hour.
	SignupWindow time.Duration
	// ResetRequestsPerIP is the number of password-reset requests from one
	// client within ResetRequestWindow. Default 3.
	ResetRequestsPerIP int
	// ResetRequestsPerAccount is the number of password-reset requests for
	// one email address within ResetRequestWindow. Default 3.
	ResetRequestsPerAccount int
	// ResetRequestWindow is the window of the two reset limits. Default 1
	// hour.
	ResetRequestWindow time.Duration
	// HashPerIP bounds the requests with password-hash work (login,
	// sign-up, reset confirmation, password change, the admin's password
	// re-entry and admin-set password) that one client may have in flight
	// at the same time. A request over it is answered 429 at once and does
	// not wait for a hash slot. With the default of 2 and the process-wide
	// limit of 4 hashes at a time (auth.HashLimits), one client address can
	// never hold more than half of the slots. Default 2.
	HashPerIP int
	// RateLimitMaxKeys bounds the number of keys (client addresses, typed or
	// stored email addresses, user ids) each rate limiter keeps state for.
	// A full counting table never refuses a request (the table of HashPerIP
	// below is the exception). When a limiter is full, the
	// entry counted least recently is evicted to admit a new one (that key
	// starts again with a fresh budget). The one exception is the table of
	// failed logins per account (LoginFailuresPerAccount): it makes room by
	// failures (an entry survives one pass of the table per failure after
	// its first), and only final failures change it (logins that are given
	// back leave no trace), so that pushing out e failures of one account
	// costs at least e·(RateLimitMaxKeys-1) counted failed logins of other
	// keys; a log line (at most one a minute) says when it pushes out
	// entries that still have failures in their window. The tables of
	// failed logins per account and of reset requests per address count any
	// typed string, valid address or not; the sign-up table is keyed by the
	// client address. The work per request does not grow with the size on
	// average; a single failure can make the failure table look at up to
	// (LoginFailuresPerAccount-1)·RateLimitMaxKeys+1 entries when it uses up
	// credit earlier failures paid for. Default DefaultRateLimitMaxKeys,
	// sized to the server's memory budget (RateLimitBytesPerKey).
	// It also bounds the table of HashPerIP, which holds an entry only while
	// a client has hash work in flight; when that table is full, a client
	// without an entry is refused with 429.
	RateLimitMaxKeys int
	// UserActionsPerHour is the number of mutating actions of the user area
	// (POST /tokens, /tokens/{id}/revoke, /reservations,
	// /reservations/{subdomain}/release and /settings/password, together)
	// one signed-in user may send within an hour, whatever their outcome.
	// It bounds how fast one account can add rows to api_tokens and
	// audit_log, which are never pruned, and run password changes. Over it
	// the answer is 429 with Retry-After. Default 120.
	UserActionsPerHour int
	// MaxRequestBodyBytes is the largest request body the frontend reads; a
	// larger one is answered with 413 before the CSRF check reads it.
	// Multipart bodies are always refused with 415. Default 64 KiB.
	MaxRequestBodyBytes int64
	// MailQueueSize is the number of mails waiting for the background
	// sender. Handlers never wait for SMTP: they put the mail in this queue
	// and answer; a mail that finds the queue full is dropped and logged.
	// Zero or a negative value selects the default, 256.
	MailQueueSize int
	// UnauthenticatedAuditRowsPerMinute bounds the audit rows that requests
	// without a login can cause, together for the whole handler: failed
	// logins (auth.login.failure), password-reset requests
	// (auth.password.reset.request) and sign-ups that filled the honeypot
	// field (auth.signup.honeypot). Beyond it in a minute (clock minutes)
	// a row is not written but counted; after the minute one row of its own
	// (auditDroppedAction, no address) says how many were dropped, and one
	// log line. Rows of a signed-in user, of an admin and of a successful
	// login, sign-up, verification or reset are never dropped. Zero selects
	// the default (120), a negative value switches the bound off.
	UnauthenticatedAuditRowsPerMinute int

	// now is the clock of the rate limiters; nil selects time.Now. Tests in
	// this package set it.
	now func() time.Time
	// accountKeyOf replaces accountKey in tests (nil: accountKey). It lets a
	// test give two spellings of one stored address different keys, which
	// in production needs letters that Go and the database lower-case
	// differently.
	accountKeyOf func(email string) string
	// dummyVerify replaces auth.DummyVerify in tests (nil: auth.DummyVerify).
	dummyVerify func(ctx context.Context, password string) error
	// limiters holds the rate-limiter state of one handler. New creates it;
	// the handlers share it through their copy of Options.
	limiters *rateLimiters
	// mails is the background sender of one handler; New creates it when
	// Mailer is set.
	mails *mailQueue
	// lookupLog limits the log lines of failed session and account lookups
	// of one handler; New creates it.
	lookupLog *lookupErrorLog
	// audits is the budget of UnauthenticatedAuditRowsPerMinute of one
	// handler; New creates it when Audit is set.
	audits *auditBudget
	// SignupMode is cfg.Auth.SignupMode(): "open", "approval" or "closed".
	SignupMode string

	// Directory and DirectoryVerifier enable GET /api/v1/directory (see
	// DirectoryPath): the listed services, for a request with a valid API
	// token. Both must be set; with either nil the path does not exist.
	Directory         *Directory
	DirectoryVerifier DirectoryVerifier
}

// New builds the frontend http.Handler.
func New(opts Options) http.Handler {
	opts.limiters = newRateLimiters(opts)
	opts.lookupLog = newLookupErrorLog()
	if opts.Mailer != nil {
		opts.mails = newMailQueue(opts.Mailer, opts.MailQueueSize, opts.now)
	}
	if opts.Audit != nil {
		opts.audits = newHandlerAuditBudget(opts, opts.Audit)
	}

	r := chi.NewRouter()
	// No middleware.RealIP: tunneld terminates TLS itself, so headers such as
	// X-Forwarded-For come from the client and must not decide its address.
	// clientIP reads the peer of the connection.
	r.Use(middleware.RequestID, middleware.Recoverer, securityHeaders,
		rejectDuplicateCookies(opts.CSRFSecure),
		limitRequestBody(opts.maxRequestBodyBytes()))

	// Static assets (CSS + JS bundled into binary via go:embed) — no CSRF.
	sub, err := fs.Sub(staticFS, "web/static")
	if err != nil {
		panic("frontend: static subFS: " + err.Error())
	}
	r.Handle("/_static/*", http.StripPrefix("/_static/", http.FileServer(http.FS(filesOnlyFS{sub}))))

	// Resolve / generate the CSRF key.
	csrfKey := opts.CSRFKey
	if len(csrfKey) == 0 {
		csrfKey = make([]byte, 32)
		if _, err := rand.Read(csrfKey); err != nil {
			panic("frontend: csrf key generation: " + err.Error())
		}
		log.Printf("frontend: WARNING: CSRFKey not configured, generated a random in-memory key (tests-only; production must configure one)")
	}
	if len(csrfKey) != 32 {
		panic("frontend: CSRFKey must be exactly 32 bytes")
	}

	// The one CSRF middleware of the handler. The user routes and the admin
	// area use this same value.
	csrfProtect := csrf.Protect(csrfKey,
		csrf.CookieName(csrfCookieName(opts.CSRFSecure)),
		csrf.Secure(opts.CSRFSecure),
		csrf.SameSite(csrf.SameSiteLaxMode),
		csrf.HttpOnly(true),
		csrf.Path("/"),
	)
	withCSRF := func(next http.Handler) http.Handler {
		protected := csrfProtect(next)
		if opts.CSRFSecure {
			return protected
		}
		// In test/dev mode (no HTTPS) mark requests as plaintext so gorilla/csrf
		// skips its Referer-origin enforcement, which otherwise rejects every
		// httptest POST with "referer not supplied".
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			protected.ServeHTTP(w, csrf.PlaintextHTTPRequest(req))
		})
	}

	// Admin routes — outside requireAuth and requireVerifiedEmail (admins
	// operate regardless of their own verification status). requireAdmin runs
	// first: it checks the session itself and answers the router's standard
	// 404 to everybody but an active admin. Only then comes the CSRF check,
	// so that a non-admin never meets it, and /admin answers with the same
	// status, body and headers as a path that does not exist.
	r.Route("/admin", func(r chi.Router) {
		r.Use(requireAdmin(opts.Sessions, opts.Users, opts.CSRFSecure, opts.lookupLog))
		r.Use(withCSRF)
		r.Use(adminPendingCount(opts))
		r.Get("/", adminIndex(opts))
		r.Get("/users", adminUsersPage(opts))
		r.Get("/users/{id}", adminUserDetailPage(opts))
		r.Post("/users/{id}/verify", adminUserVerify(opts))
		r.Post("/users/{id}/approve", adminUserApprove(opts))
		r.Post("/users/{id}/disable", adminUserDisable(opts))
		r.Post("/users/{id}/enable", adminUserEnable(opts))
		r.Post("/users/{id}/promote", adminUserPromote(opts))
		r.Post("/users/{id}/demote", adminUserDemote(opts))
		r.Post("/users/{id}/reset-password", adminUserResetPassword(opts))
		r.Post("/users/{id}/revoke-tokens", adminUserRevokeTokens(opts))
		r.Get("/approvals", adminApprovalsPage(opts))
		r.Post("/approvals", adminApprovalsSubmit(opts))
		r.Get("/connections", adminConnectionsPage(opts))
		r.Get("/connections/status", adminConnectionsStatus(opts))
		r.Post("/connections/{session_id}/kill", adminConnectionKill(opts))
		r.Get("/reservations", adminReservationsPage(opts))
		r.Post("/reservations/grant", adminReservationsGrant(opts))
		r.Post("/reservations/{type}/revoke", adminReservationsRevoke(opts))
	})

	// The directory API: token-authenticated, read-only, no cookies, so
	// outside the CSRF protection.
	if opts.Directory != nil && opts.DirectoryVerifier != nil {
		r.Get(DirectoryPath, directoryHandler(opts))
	}

	// Everything else is behind CSRF protection.
	r.Group(func(r chi.Router) {
		r.Use(withCSRF)

		// Public routes.
		r.Get("/", redirectRoot(opts))
		r.Get("/signup", signupPage(opts))
		r.Post("/signup", signupSubmit(opts))
		r.Get("/login", loginPage(opts))
		r.Post("/login", loginSubmit(opts))
		r.Post("/logout", logoutSubmit(opts))
		// /verify is public: a user clicking the email link in a different
		// browser than the one they signed up in shouldn't be redirected to
		// /login. Consuming the token is itself the authentication here.
		// GET only shows a confirmation page; the POST from it consumes.
		r.Get("/verify", verifyPage(opts))
		r.Post("/verify", verifySubmit(opts))
		r.Get("/forgot-password", forgotPage(opts))
		r.Post("/forgot-password", forgotSubmit(opts))
		r.Get("/reset", resetPage(opts))
		r.Post("/reset", resetSubmit(opts))

		// Authenticated routes.
		r.Group(func(r chi.Router) {
			r.Use(requireAuth(opts.Sessions, opts.CSRFSecure, opts.lookupLog))
			r.Get("/dashboard", dashboardPage(opts))
			r.Get("/tunnels", tunnelsPage(opts))
			r.Get("/tunnels/status", tunnelsStatusFragment(opts))
			r.Get("/tokens", tokensPage(opts))
			r.Get("/reservations", reservationsPage(opts))
			r.Get("/settings", settingsPage(opts))
			// The resend has its own limit (one mail a minute per user).
			r.Post("/verify/resend", verifyResendHandler(opts))

			// The mutating actions of the user area share one budget per
			// user (Options.UserActionsPerHour); a refusal is shown where
			// the page shows its other errors.
			limitTokens := limitUserActions(opts, refuseInErrorField(templates.TokensError))
			limitReservations := limitUserActions(opts, refuseInErrorField(templates.ReservationsError))
			r.With(limitUserActions(opts, refuseOnSettingsPage(opts))).Post("/settings/password", settingsChangePassword(opts))

			// Taking back what the account holds needs a login only: an
			// account with an unverified address (one an operator created,
			// or one whose owner cannot verify) must still be able to
			// revoke its tokens and release its names.
			r.With(limitTokens).Post("/tokens/{id}/revoke", tokensRevoke(opts))
			r.With(limitReservations).Post("/reservations/{subdomain}/release", reservationsRelease(opts))

			// Creating is gated behind a verified email and, in approval
			// and closed mode, an approved account. GET pages remain
			// reachable so the user can see the dashboard banner that
			// prompts them to resend the verification mail or says that
			// the account waits for approval.
			r.Group(func(r chi.Router) {
				r.Use(requireVerifiedEmail(opts.Users, opts.Verifications != nil, opts.lookupLog))
				r.Use(requireApproved(opts.Users, opts.approvalRequired(), opts.lookupLog))
				r.With(limitTokens).Post("/tokens", tokensCreate(opts))
				r.With(limitReservations).Post("/reservations", reservationsCreate(opts))
			})
		})
	})

	return &frontendHandler{Handler: r, limiters: opts.limiters, mails: opts.mails, audits: opts.audits}
}

// frontendHandler is the handler New returns: the router plus the state
// that belongs to this handler, kept reachable for the tests of the package.
type frontendHandler struct {
	http.Handler
	limiters *rateLimiters
	mails    *mailQueue   // nil without a mailer
	audits   *auditBudget // nil without an audit service
}

// redirectRoot sends GET / to /dashboard when authenticated, /login otherwise.
func redirectRoot(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if raw, ok := readSessionCookie(r, opts.CSRFSecure); ok {
			_, err := opts.Sessions.Lookup(r.Context(), raw)
			if err == nil {
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
				return
			}
			if !errors.Is(err, sessions.ErrInvalidSession) {
				sessionLookupFailed(w, err, opts.lookupLog)
				return
			}
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// filesOnlyFS hides directories: opening one fails with fs.ErrNotExist, so
// http.FileServer answers 404 instead of a directory listing.
type filesOnlyFS struct{ fs.FS }

func (f filesOnlyFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		_ = file.Close()
		return nil, fs.ErrNotExist
	}
	return file, nil
}

// Defaults of the rate limits and bounds in Options.
const (
	DefaultLoginFailuresPerAccount = 10
	DefaultLoginFailuresPerIP      = 30
	DefaultLoginFailureWindow      = 15 * time.Minute
	DefaultLoginsPerAccount        = 30
	DefaultSignupsPerIP            = 5
	DefaultSignupWindow            = time.Hour
	DefaultResetRequestsPerIP      = 3
	DefaultResetRequestsPerAccount = 3
	DefaultResetRequestWindow      = time.Hour
	DefaultHashPerIP               = 2
	DefaultUserActionsPerHour      = 120
	DefaultRateLimitMaxKeys        = 1600 // sized by RateLimitBytesPerKey to the server's memory budget
	DefaultMaxRequestBodyBytes     = 64 << 10

	DefaultUnauthenticatedAuditRowsPerMinute = 120
)

// maxRequestBodyBytes resolves Options.MaxRequestBodyBytes; 0 or less in the
// result means no size limit.
func (o Options) maxRequestBodyBytes() int64 {
	switch {
	case o.MaxRequestBodyBytes == 0:
		return DefaultMaxRequestBodyBytes
	case o.MaxRequestBodyBytes < 0:
		return 0
	}
	return o.MaxRequestBodyBytes
}
