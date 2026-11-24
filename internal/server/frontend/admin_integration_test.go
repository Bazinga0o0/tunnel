package frontend

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// cspNonceRE finds the per-request nonce in a Content-Security-Policy.
var cspNonceRE = regexp.MustCompile(`'nonce-[^']*'`)

// comparableHeaders returns the response headers without what differs from
// one request to the next anyway: the CSP nonce and a request id.
func comparableHeaders(h http.Header) http.Header {
	out := h.Clone()
	out.Del("X-Request-Id")
	if csp := out.Get("Content-Security-Policy"); csp != "" {
		out.Set("Content-Security-Policy", cspNonceRE.ReplaceAllString(csp, "'nonce-…'"))
	}
	return out
}

// rawRequest sends a request with exactly the given cookies; a POST carries
// an empty form and no CSRF token.
func (e *adminTestEnv) rawRequest(t *testing.T, method, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if method == http.MethodPost {
		req = httptest.NewRequest(method, path, strings.NewReader(url.Values{"x": {"1"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

// ---- 3a, 3f: the admin area answers exactly like a page that does not exist ----

func TestAdminAreaIsIndistinguishableFromAMissingPage(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "plain cookies"
		if secure {
			name = "__Host- cookies"
		}
		t.Run(name, func(t *testing.T) {
			e := newAdminTestEnv(t, func(o *Options) { o.CSRFSecure = secure })
			user := e.insertUser(t, "not-an-admin@example.com", true)

			callers := map[string][]*http.Cookie{
				"no session":            nil,
				"logged-in non-admin":   {e.login(t, user)},
				"unknown session value": {{Name: sessionCookieName(secure), Value: "not-a-session"}},
			}
			if secure {
				// Cookies under the plain names, which the secure mode expires
				// on sight: the expiry must look the same on both paths.
				callers["old plain-name cookies"] = []*http.Cookie{
					{Name: sessionCookieNamePlain, Value: "old"},
					{Name: csrfCookieNamePlain, Value: "old"},
				}
			}

			for who, cookies := range callers {
				for _, method := range []string{http.MethodGet, http.MethodPost} {
					missing := e.rawRequest(t, method, "/no-such-page-anywhere", cookies...)
					require.Equal(t, http.StatusNotFound, missing.Code, "%s %s: baseline", who, method)
					for _, path := range []string{"/admin", "/admin/", "/admin/users/1", "/admin/users/1/disable",
						"/admin/reservations/grant", "/admin/connections/status", "/admin/no-such-admin-page"} {
						got := e.rawRequest(t, method, path, cookies...)
						assert.Equal(t, missing.Code, got.Code, "%s: %s %s: status", who, method, path)
						assert.Equal(t, missing.Body.String(), got.Body.String(), "%s: %s %s: body", who, method, path)
						assert.Equal(t, comparableHeaders(missing.Header()), comparableHeaders(got.Header()),
							"%s: %s %s: headers", who, method, path)
					}
				}
			}

			// The admin still gets the page.
			w := e.rawRequest(t, http.MethodGet, "/admin", e.adminCookie)
			require.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), "Admin overview")
		})
	}
}

// closedPool returns a pool that is already closed: every query on it fails.
func closedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://nobody@127.0.0.1:1/none")
	require.NoError(t, err)
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	p.Close()
	return p
}

// When the gate cannot look the session or the account up, it answers like
// a page that does not exist as well (fail closed), with the same status,
// body and headers: a database error must not tell the admin area apart.
// The error goes to the log.
func TestAdminGateDatabaseErrorsLookLikeAMissingPage(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, broken := range []string{"session lookup", "admin check"} {
			name := broken + ", plain cookies"
			if secure {
				name = broken + ", __Host- cookies"
			}
			t.Run(name, func(t *testing.T) {
				e := newAdminTestEnv(t, func(o *Options) {
					o.CSRFSecure = secure
					if broken == "session lookup" {
						o.Sessions = sessions.NewService(closedPool(t))
					} else {
						o.Users = users.NewService(closedPool(t))
					}
				})
				logged := captureLog(t)
				for _, method := range []string{http.MethodGet, http.MethodPost} {
					missing := e.rawRequest(t, method, "/no-such-page-anywhere", e.adminCookie)
					require.Equal(t, http.StatusNotFound, missing.Code, "%s: baseline", method)
					for _, path := range []string{"/admin", "/admin/users/1", "/admin/users/1/disable", "/admin/no-such-admin-page"} {
						got := e.rawRequest(t, method, path, e.adminCookie)
						assert.Equal(t, missing.Code, got.Code, "%s %s: status", method, path)
						assert.Equal(t, missing.Body.String(), got.Body.String(), "%s %s: body", method, path)
						assert.Equal(t, comparableHeaders(missing.Header()), comparableHeaders(got.Header()),
							"%s %s: headers", method, path)
					}
				}
				assert.Contains(t, logged.String(), "admin: "+broken)
			})
		}
	}
}

// A failing lookup in the middleware is logged at most once per interval for
// a handler, however many requests meet it: a database outage must not
// write one line per request.
func TestLookupErrorsAreLoggedWithALimit(t *testing.T) {
	e := newAdminTestEnv(t, func(o *Options) { o.Sessions = sessions.NewService(closedPool(t)) })
	logged := captureLog(t)
	for i := 0; i < 5; i++ {
		require.Equal(t, http.StatusServiceUnavailable, e.rawRequest(t, http.MethodGet, "/dashboard", e.adminCookie).Code)
		require.Equal(t, http.StatusServiceUnavailable, e.rawRequest(t, http.MethodGet, "/", e.adminCookie).Code)
		require.Equal(t, http.StatusNotFound, e.rawRequest(t, http.MethodGet, "/admin", e.adminCookie).Code)
	}
	assert.Equal(t, 1, strings.Count(logged.String(), "session lookup"), "one line for fifteen failures: %s", logged.String())
}

// The account lookup of the verified-email gate goes through the same limit:
// a database outage behind a working session lookup writes one line, and
// every request still gets the answer it got before (500 with the fixed
// text; the error text never reaches the client).
func TestVerifiedEmailGateLookupErrorsAreLoggedWithALimit(t *testing.T) {
	s := newStack(t, withMail, func(o *Options, _ *stack) { o.Users = users.NewService(closedPool(t)) })
	id := s.createUser(t, "gated@example.com", "pw12345678")
	raw, _, err := s.sess.Create(context.Background(), id, "test", netip.Addr{}, time.Hour)
	require.NoError(t, err)
	cookie := &http.Cookie{Name: sessionCookieName(false), Value: raw}
	// The token comes from the login page: every page of a logged-in user
	// needs the broken account lookup.
	token, csrfCookie := getCSRF(t, s.h, nil, "/login")
	logged := captureLog(t)
	for i := 0; i < 5; i++ {
		form := url.Values{"name": {"laptop"}, "gorilla.csrf.Token": {token}}
		req := httptest.NewRequest(http.MethodPost, "/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrfCookie)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.h.ServeHTTP(w, req)
		require.Equal(t, http.StatusInternalServerError, w.Code, "request %d", i)
		require.Equal(t, msgInternal+"\n", w.Body.String(), "request %d", i)
		assert.NotContains(t, w.Body.String(), "closed pool")
	}
	assert.Equal(t, 1, strings.Count(logged.String(), "verified-email check: look up user"), "one line for five failures: %s", logged.String())
}

// A lookup that fails because the client went away (its request context was
// cancelled) is no fault of the server and writes no log line. The answers
// stay the same.
func TestLookupErrorOfAClientThatWentAwayIsNotLogged(t *testing.T) {
	e := newAdminTestEnv(t)
	logged := captureLog(t)
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	for path, want := range map[string]int{"/dashboard": http.StatusServiceUnavailable, "/": http.StatusServiceUnavailable, "/admin": http.StatusNotFound} {
		req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(gone)
		req.AddCookie(e.adminCookie)
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, req)
		assert.Equal(t, want, w.Code, path)
	}
	assert.NotContains(t, logged.String(), "lookup")
}

// An active admin's POST without a CSRF token, or with a wrong one, is
// refused with 403 and changes nothing, in both cookie modes.
func TestAdminPostWithoutAValidCSRFTokenIsRefused(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "plain cookies"
		base := "" // httptest's default: http://example.com
		if secure {
			name, base = "__Host- cookies", secureBase
		}
		t.Run(name, func(t *testing.T) {
			e := newAdminTestEnv(t, func(o *Options) { o.CSRFSecure = secure })
			ctx := context.Background()
			target := e.insertUser(t, "target@example.com", true)
			token, csrfCookie := csrfFrom(t, e.h, base+"/login", csrfCookieName(secure))
			wrong := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 64))

			post := func(token string, cookies ...*http.Cookie) int {
				t.Helper()
				form := url.Values{}
				if token != "" {
					form.Set("gorilla.csrf.Token", token)
				}
				req := httptest.NewRequest(http.MethodPost, base+"/admin/users/"+itoa(target)+"/disable", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if secure {
					req.Header.Set("Origin", secureBase)
				}
				for _, c := range cookies {
					req.AddCookie(c)
				}
				w := httptest.NewRecorder()
				e.h.ServeHTTP(w, req)
				return w.Code
			}
			disabled := func() bool {
				t.Helper()
				u, err := e.users.FindByID(ctx, target)
				require.NoError(t, err)
				return u.DisabledAt.Valid
			}

			assert.Equal(t, http.StatusForbidden, post("", e.adminCookie), "no token, no CSRF cookie")
			assert.Equal(t, http.StatusForbidden, post("", e.adminCookie, csrfCookie), "no token")
			assert.Equal(t, http.StatusForbidden, post(wrong, e.adminCookie, csrfCookie), "wrong token")
			assert.False(t, disabled(), "a refused request changes nothing")
			assert.Empty(t, e.auditRows(t, "admin.user.disable"))

			// Control: the same request with the right token goes through.
			require.Equal(t, http.StatusSeeOther, post(token, e.adminCookie, csrfCookie))
			assert.True(t, disabled())
		})
	}
}

// ---- 3b: password re-entry counts against the per-account login budget ----

// loginAccountCount is the number of failures the per-account login limiter
// holds for email.
func (e *adminTestEnv) loginAccountCount(email string) int {
	return e.h.(*frontendHandler).limiters.loginAccount.count(accountKey(email))
}

func TestAdminPasswordReentryIsThrottled(t *testing.T) {
	e := newAdminTestEnv(t, func(o *Options) { o.LoginFailuresPerAccount = 3 })
	ctx := context.Background()
	target := e.insertUser(t, "target@example.com", true)
	base := "/admin/users/" + itoa(target)
	wrong := url.Values{"current_password": {"not-my-password"}}
	right := url.Values{"current_password": {adminTestPassword}}

	require.Equal(t, http.StatusForbidden, e.post(t, e.adminCookie, base+"/promote", wrong).Code)
	require.Equal(t, http.StatusForbidden, e.post(t, e.adminCookie, base+"/promote", wrong).Code)
	require.Equal(t, 2, e.loginAccountCount("admin@example.com"), "each failed re-entry counts")

	// A successful re-entry is handled like a successful login: it does not
	// count.
	require.Equal(t, http.StatusSeeOther, e.post(t, e.adminCookie, base+"/promote", right).Code)
	assert.Equal(t, 2, e.loginAccountCount("admin@example.com"))

	require.Equal(t, http.StatusForbidden, e.post(t, e.adminCookie, base+"/demote", wrong).Code)
	require.Equal(t, 3, e.loginAccountCount("admin@example.com"))

	// Over the limit: 429 even with the right password, and nothing changes.
	w := e.post(t, e.adminCookie, base+"/demote", right)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	// The text is true whichever limit refused (this one: the account's).
	assert.Contains(t, w.Body.String(), "Too many failed password attempts. Try again later. Nothing was changed.")
	assert.NotContains(t, w.Body.String(), "for your account")
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	u, err := e.users.FindByID(ctx, target)
	require.NoError(t, err)
	assert.True(t, u.IsAdmin, "the refused demote changed nothing")
	assert.Empty(t, e.auditRows(t, "admin.user.demote"))

	before := e.passwordHash(t, target)
	w = e.post(t, e.adminCookie, base+"/reset-password", url.Values{
		"new_password": {"a-brand-new-password"}, "current_password": {adminTestPassword},
	})
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, before, e.passwordHash(t, target))
	assert.Equal(t, 3, e.loginAccountCount("admin@example.com"), "a refused attempt is not counted again")
}

func TestAdminLoginAndPasswordReentryShareOneBudget(t *testing.T) {
	e := newAdminTestEnv(t, func(o *Options) { o.LoginFailuresPerAccount = 3 })
	target := e.insertUser(t, "target@example.com", true)
	promote := "/admin/users/" + itoa(target) + "/promote"
	login := func(password string) int {
		return e.post(t, nil, "/login", url.Values{"email": {"admin@example.com"}, "password": {password}}).Code
	}

	require.Equal(t, http.StatusUnauthorized, login("not-my-password"))
	require.Equal(t, http.StatusForbidden, e.post(t, e.adminCookie, promote, url.Values{"current_password": {"wrong-1"}}).Code)
	require.Equal(t, http.StatusForbidden, e.post(t, e.adminCookie, promote, url.Values{"current_password": {"wrong-2"}}).Code)

	// One login failure and two re-entry failures fill the budget of 3: both
	// the admin form and the login are refused now, with the right password.
	assert.Equal(t, http.StatusTooManyRequests,
		e.post(t, e.adminCookie, promote, url.Values{"current_password": {adminTestPassword}}).Code)
	assert.Equal(t, http.StatusTooManyRequests, login(adminTestPassword))
	u, err := e.users.FindByID(context.Background(), target)
	require.NoError(t, err)
	assert.False(t, u.IsAdmin)
}

// ---- 3d: service errors go through the web UI's error mapping ----

// failUpdates makes statements on table fail with the given SQLSTATE while
// cond holds, until the test ends. The trigger name starts with
// dbtest_fail_delete_ so that dbtest.Pool removes it should the test be
// killed before its cleanup.
func (e *adminTestEnv) failUpdates(t *testing.T, table, event, cond, sqlstate string) {
	t.Helper()
	ctx := context.Background()
	fn := "admin_test_fail_" + table
	_, err := e.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION `+fn+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		IF `+cond+` THEN RAISE EXCEPTION 'injected failure' USING ERRCODE = '`+sqlstate+`'; END IF;
		RETURN NEW; END $$`)
	require.NoError(t, err)
	trg := "dbtest_fail_delete_admin_" + table
	_, err = e.pool.Exec(ctx, `CREATE TRIGGER `+trg+` BEFORE `+event+` ON `+table+` FOR EACH ROW EXECUTE FUNCTION `+fn+`()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = e.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+trg+` ON `+table)
		_, _ = e.pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+fn+`()`)
	})
}

func TestAdminActionsAnswerTryAgainForTransientDatabaseFailures(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	target := e.insertUser(t, "target@example.com", true)
	e.insertUser(t, "owner@example.com", true)
	sess := &fakeCloseableSession{id: "target-session", userID: target}
	require.NoError(t, e.reg.AddSession(sess, registry.SessionLimits{}))

	// A deadlock while disabling: 503 with Retry-After and the detail page,
	// nothing done.
	e.failUpdates(t, "users", "UPDATE", "NEW.disabled_at IS NOT NULL AND OLD.disabled_at IS NULL", "40P01")
	w := e.post(t, e.adminCookie, "/admin/users/"+itoa(target)+"/disable", nil)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	assert.Contains(t, w.Body.String(), "The server is busy")
	assert.NotContains(t, w.Body.String(), "injected failure")
	u, err := e.users.FindByID(ctx, target)
	require.NoError(t, err)
	assert.False(t, u.DisabledAt.Valid)
	assert.False(t, sess.closed)
	assert.Empty(t, e.auditRows(t, "admin.user.disable"))

	// A serialisation failure while granting: 503 with Retry-After and the
	// reservations page.
	e.failUpdates(t, "reserved_subdomains", "INSERT", "true", "40001")
	w = e.grant(t, "subdomain", "retry-me", "owner@example.com")
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	assert.Contains(t, w.Body.String(), "Please try again in a moment")
	assert.NotContains(t, w.Body.String(), "injected failure")
	assert.Empty(t, e.auditRows(t, "admin.reservation.grant"))
}

// A revoke of all tokens that a transient database failure stops part-way
// has changed something: some tokens are revoked and the tunnels are closed.
// The page says so instead of the busy message's "Nothing was changed".
func TestAdminRevokeTokensStoppedByATransientFailureSaysWhatWasDone(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	target := e.insertUser(t, "half-revoked@example.com", true)
	_, older, err := e.tokens.Issue(ctx, target, "older")
	require.NoError(t, err)
	_, newer, err := e.tokens.Issue(ctx, target, "newer")
	require.NoError(t, err)
	// Tokens are revoked newest first; make the order certain.
	_, err = e.pool.Exec(ctx, `UPDATE api_tokens SET created_at = now() - interval '1 hour' WHERE id = $1`, older.ID)
	require.NoError(t, err)
	sess := &fakeCloseableSession{id: "half-revoked-session", userID: target}
	require.NoError(t, e.reg.AddSession(sess, registry.SessionLimits{}))

	// A deadlock on the revoke of the older token.
	e.failUpdates(t, "api_tokens", "UPDATE", "OLD.id = "+itoa(older.ID), "40P01")
	w := e.post(t, e.adminCookie, "/admin/users/"+itoa(target)+"/revoke-tokens", nil)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	body := w.Body.String()
	assert.NotContains(t, body, "Nothing was changed")
	assert.Contains(t, body, "Not every API token could be revoked")
	assert.Contains(t, body, "The tokens revoked so far stay revoked")
	assert.NotContains(t, body, "injected failure")

	active, err := e.tokens.ListActiveByUser(ctx, target)
	require.NoError(t, err)
	require.Len(t, active, 1, "the newer token was revoked before the failure")
	assert.Equal(t, older.ID, active[0].ID)
	assert.NotEqual(t, newer.ID, active[0].ID)
	assert.True(t, sess.closed, "the tunnels are closed even so")
}

// ---- 3c: the global middleware covers the admin area ----

// adminExpectedCSP is the Content-Security-Policy of every response, nonce
// masked as comparableHeaders does.
const adminExpectedCSP = "default-src 'self'; style-src 'self'; script-src 'self' 'nonce-…'; img-src 'self' data:; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"

func TestAdminRoutesAreCoveredByTheGlobalMiddleware(t *testing.T) {
	e := newAdminTestEnv(t)
	target := e.insertUser(t, "target@example.com", false)
	verify := "/admin/users/" + itoa(target) + "/verify"

	t.Run("body over 64 KiB: 413, nothing done", func(t *testing.T) {
		token, csrfCookie := getCSRF(t, e.h, nil, "/login")
		form := url.Values{"gorilla.csrf.Token": {token}, "pad": {strings.Repeat("x", 70<<10)}}
		req := httptest.NewRequest(http.MethodPost, verify, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrfCookie)
		req.AddCookie(e.adminCookie)
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
		assert.Empty(t, e.auditRows(t, "admin.user.verify"))
	})

	t.Run("multipart body: 415", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, verify, strings.NewReader("--b\r\n\r\nx\r\n--b--\r\n"))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
		req.AddCookie(e.adminCookie)
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnsupportedMediaType, w.Code)
	})

	t.Run("duplicate session cookie: 400", func(t *testing.T) {
		w := e.rawRequest(t, http.MethodGet, "/admin", e.adminCookie,
			&http.Cookie{Name: sessionCookieName(false), Value: "planted"})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.NotContains(t, w.Body.String(), "Admin overview")
	})

	t.Run("security headers and no-store on admin responses", func(t *testing.T) {
		responses := map[string]*httptest.ResponseRecorder{
			"page":     e.rawRequest(t, http.MethodGet, "/admin", e.adminCookie),
			"detail":   e.rawRequest(t, http.MethodGet, "/admin/users/"+itoa(target), e.adminCookie),
			"fragment": e.rawRequest(t, http.MethodGet, "/admin/connections/status", e.adminCookie),
			"action":   e.post(t, e.adminCookie, verify, nil),
		}
		for name, w := range responses {
			require.Less(t, w.Code, 400, "%s: %d", name, w.Code)
			h := comparableHeaders(w.Header())
			assert.Equal(t, adminExpectedCSP, h.Get("Content-Security-Policy"), name)
			assert.Equal(t, "same-origin", h.Get("Cross-Origin-Opener-Policy"), name)
			assert.Equal(t, "same-origin", h.Get("Cross-Origin-Resource-Policy"), name)
			assert.Equal(t, "DENY", h.Get("X-Frame-Options"), name)
			assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"), name)
			assert.Equal(t, "no-store", h.Get("Cache-Control"), "%s: an admin response is not cached", name)
		}
	})
}
