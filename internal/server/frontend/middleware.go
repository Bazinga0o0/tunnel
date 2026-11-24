package frontend

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"

	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

type ctxKey string

const (
	ctxUserID    ctxKey = "user_id"
	ctxSessionID ctxKey = "session_id"
	ctxCSPNonce  ctxKey = "csp_nonce"
)

// userIDFromContext returns the authenticated user's ID, or 0 if unauthenticated.
func userIDFromContext(ctx context.Context) int64 {
	v, _ := ctx.Value(ctxUserID).(int64)
	return v
}

// sessionIDFromContext returns the sha256 session ID (bytea), or nil if unauthenticated.
func sessionIDFromContext(ctx context.Context) []byte {
	v, _ := ctx.Value(ctxSessionID).([]byte)
	return v
}

// CSPNonceFromContext returns the per-request CSP nonce.
func CSPNonceFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxCSPNonce).(string)
	return v
}

// requireAuth is chi middleware: if no valid session cookie, redirect to /login.
// secure selects the cookie name and the Secure attribute on the cleared
// cookie (must match the production/test deployment — false for plain-HTTP
// tests).
//
// Every response behind it is marked Cache-Control: no-store, so that pages
// with account data (and fragments with a new API token) do not stay in a
// browser or proxy cache.
//
// A session that does not exist (or expired, or belongs to a disabled
// account) clears the cookie, except on an htmx request (HX-Request: true),
// which only gets the redirect: such a request can carry the cookie of a
// session that a password change replaced a moment ago, and clearing it
// could delete the new cookie. A failed lookup (the database is unreachable)
// answers 503 and leaves the cookie alone: a database outage must not log
// everybody out. Its log line goes through lookupLog.
func requireAuth(svc *sessions.Service, secure bool, lookupLog *lookupErrorLog) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			raw, ok := readSessionCookie(r, secure)
			if !ok {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			row, err := svc.Lookup(r.Context(), raw)
			if err != nil {
				if !errors.Is(err, sessions.ErrInvalidSession) {
					sessionLookupFailed(w, err, lookupLog)
					return
				}
				// An htmx request (a status poll, a button) may still carry
				// the cookie of a session that a password change replaced a
				// moment ago; clearing it here could delete the new cookie
				// of the same name. It only gets the redirect.
				if r.Header.Get("HX-Request") != "true" {
					clearSessionCookie(w, secure)
				}
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			ctx := context.WithValue(r.Context(), ctxUserID, row.UserID)
			ctx = context.WithValue(ctx, ctxSessionID, row.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// sessionLookupFailed answers a session lookup that failed for another
// reason than an unknown session: 503 with Retry-After, the cookie is not
// touched. The error goes to the log only, through lookupLog.
func sessionLookupFailed(w http.ResponseWriter, err error, lookupLog *lookupErrorLog) {
	lookupLog.printf(err, "frontend: session lookup: %v", err)
	setRetryAfter(w, tryAgainAfter)
	http.Error(w, msgTryAgain, http.StatusServiceUnavailable)
}

// lookupErrorLog writes the log lines of session and account lookups that
// fail in the middleware. Such a failure comes with every request while the
// database is down, so the lines of one handler are limited to one per
// edgeguard.LogInterval, each with the number held back since the last. A
// lookup that failed because the client went away (its request context was
// cancelled) is no fault of the server and is not logged at all.
type lookupErrorLog struct {
	lim  *edgeguard.LogLimiter
	what string // what the lines are about, for the count of those held back
}

func newLookupErrorLog() *lookupErrorLog {
	return newLimitedErrorLog("lookup failures")
}

// newLimitedErrorLog is a lookupErrorLog for other failures; what names
// them in the count of the lines held back.
func newLimitedErrorLog(what string) *lookupErrorLog {
	return &lookupErrorLog{lim: edgeguard.NewLogLimiter(edgeguard.LogInterval), what: what}
}

// printf logs the line for err unless err is a cancellation or the limit
// holds it back.
func (l *lookupErrorLog) printf(err error, format string, args ...any) {
	if errors.Is(err, context.Canceled) {
		return
	}
	ok, suppressed := l.lim.Allow()
	if !ok {
		return
	}
	line := fmt.Sprintf(format, args...)
	if suppressed > 0 {
		line += fmt.Sprintf(" (%d more %s not logged)", suppressed, l.what)
	}
	log.Print(line)
}

// requireVerifiedEmail blocks authenticated users without a verified email
// from accessing state-changing endpoints. Unverified users are redirected
// to /dashboard where they see a banner prompting them to resend.
//
// The gate only engages when enabled=true. Test wiring that doesn't configure
// Verifications/Mailer passes enabled=false so the gate becomes a pass-through;
// otherwise every existing unverified-by-default test user would get redirected.
//
// A failed account lookup answers as serverError does; its log line goes
// through lookupLog, like those of the session lookups.
func requireVerifiedEmail(userSvc *users.Service, enabled bool, lookupLog *lookupErrorLog) func(http.Handler) http.Handler {
	if !enabled {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := userIDFromContext(r.Context())
			if userID == 0 {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			u, err := userSvc.FindByID(r.Context(), userID)
			if err != nil {
				lookupLog.printf(err, "frontend: verified-email check: look up user: %v", err)
				status, msg := failureAnswer(w, err)
				http.Error(w, msg, status)
				return
			}
			if !u.EmailVerifiedAt.Valid {
				http.Redirect(w, r, "/dashboard?needs_verification=1", http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// approvalRequired reports whether accounts need an admin's approval before
// they can create tokens and reservations: every SignupMode but "open", so
// that an unknown value fails closed. Empty (tests that do not set it)
// counts as "open".
func (o Options) approvalRequired() bool {
	return o.SignupMode != "" && o.SignupMode != "open"
}

// requireApproved blocks authenticated users whose account waits for an
// admin's approval (users.IsApproved) from creating tokens and
// reservations. They are redirected to /dashboard, where a banner says that
// the account waits.
//
// The gate only engages when enabled=true (Options.approvalRequired). A
// failed account lookup answers as in requireVerifiedEmail.
func requireApproved(userSvc *users.Service, enabled bool, lookupLog *lookupErrorLog) func(http.Handler) http.Handler {
	if !enabled {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := userIDFromContext(r.Context())
			if userID == 0 {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			u, err := userSvc.FindByID(r.Context(), userID)
			if err != nil {
				lookupLog.printf(err, "frontend: approval check: look up user: %v", err)
				status, msg := failureAnswer(w, err)
				http.Error(w, msg, status)
				return
			}
			if !users.IsApproved(u) {
				http.Redirect(w, r, "/dashboard?awaiting_approval=1", http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// securityHeaders sets HSTS, X-Frame-Options, CSP (with a per-request nonce),
// and friends on every response.
//
// Besides the sources, the CSP forbids a <base> element (base-uri), form
// targets on other origins (form-action) and plugins (object-src). COOP
// keeps windows of other origins from holding a reference to ours, CORP
// keeps other origins from embedding our responses.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(w, "entropy failed", http.StatusInternalServerError)
			return
		}
		nonce := base64.RawStdEncoding.EncodeToString(nonceBytes)

		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		csp := "default-src 'self'; style-src 'self'; script-src 'self' 'nonce-" + nonce + "'; img-src 'self' data:; connect-src 'self'; " +
			"frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
		h.Set("Content-Security-Policy", csp)

		ctx := context.WithValue(r.Context(), ctxCSPNonce, nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// limitRequestBody bounds request bodies before anything reads them; it
// runs ahead of the CSRF middleware, which parses the form of every POST
// before it compares the token.
//
// A multipart body is refused with 415: no form of this UI uses one, and Go
// would buffer up to 32 MiB of it. A body over max bytes is refused with 413.
// The body is read here, at most max bytes, so that the limit also holds
// for a body without Content-Length and the answer is a clear 413. max <= 0
// disables the size limit (multipart stays refused).
func limitRequestBody(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isMultipart(r.Header.Get("Content-Type")) {
				http.Error(w, "multipart request bodies are not accepted", http.StatusUnsupportedMediaType)
				return
			}
			if max <= 0 || r.Body == nil || r.Body == http.NoBody {
				next.ServeHTTP(w, r)
				return
			}
			if r.ContentLength > max {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
			if err != nil {
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, "bad request body", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			next.ServeHTTP(w, r)
		})
	}
}

// isMultipart reports whether a Content-Type header value names a multipart
// media type, in any letter case.
func isMultipart(contentType string) bool {
	if mediaType, _, err := mime.ParseMediaType(contentType); err == nil {
		return strings.HasPrefix(mediaType, "multipart/")
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "multipart/")
}
