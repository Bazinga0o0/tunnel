package frontend

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	"github.com/Bazinga0o0/tunnel/internal/server/passwordreset"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
	"github.com/Bazinga0o0/tunnel/internal/server/verifications"
)

// testCSRFKey is a fixed 32-byte key used across the test suite so every
// test run is deterministic. Production must configure a real key.
var testCSRFKey = []byte("0123456789abcdef0123456789abcdef")

// TestMain runs the package's tests with the cheapest argon2id cost
// (auth.UseCheapKDFForTesting). They sign up, log in and change passwords
// hundreds of times and assert what the handlers answer, count and store;
// none depends on what a hash costs, and those that need hash work in
// flight hold it with the KDF hook. At the real cost the KDF took half of
// the package's run time, about two minutes on a two-core machine.
func TestMain(m *testing.M) {
	auth.UseCheapKDFForTesting()
	os.Exit(m.Run())
}

// fakeOwnedSession implements registry.Session + UserIDer + ConnectedAter for
// tests that exercise the /tunnels/status snapshot filter without needing a
// real acceptor handshake.
type fakeOwnedSession struct {
	id          string
	userID      int64
	connectedAt time.Time
}

func (f *fakeOwnedSession) ID() string                  { return f.id }
func (f *fakeOwnedSession) UserIDValue() int64          { return f.userID }
func (f *fakeOwnedSession) ConnectedAtValue() time.Time { return f.connectedAt }

func TestTunnelsFragmentShowsOwnedTunnelsOnly(t *testing.T) {
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)

	reg := registry.New()
	h := New(Options{
		Domain:       "tunnel.localhost",
		Users:        users.NewService(pool),
		Tokens:       tokens.NewService(pool),
		Reservations: reservations.NewService(pool),
		Sessions:     sessions.NewService(pool),
		Registry:     reg,
		CSRFKey:      testCSRFKey,
		CSRFSecure:   false,
	})

	sc := doSignup(t, h, "live@b.example.com", "pw12345678")

	// Resolve the signed-up user's ID via the sessions service.
	svc := sessions.NewService(pool)
	row, err := svc.Lookup(context.Background(), sc.Value)
	require.NoError(t, err)
	userID := row.UserID

	owned := &fakeOwnedSession{id: "s1", userID: userID, connectedAt: time.Now().Add(-90 * time.Second)}
	other := &fakeOwnedSession{id: "s2", userID: userID + 1000, connectedAt: time.Now()}
	require.NoError(t, reg.RegisterHTTP("myapp", owned))
	require.NoError(t, reg.RegisterHTTP("notmine", other))

	// Page skeleton renders.
	req := httptest.NewRequest("GET", "/tunnels", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Live tunnels")

	// Fragment contains the owned tunnel, not the other user's.
	req = httptest.NewRequest("GET", "/tunnels/status", nil)
	req.AddCookie(sc)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "myapp")
	assert.Contains(t, body, "https://myapp.tunnel.localhost")
	assert.NotContains(t, body, "notmine")
}

func TestTunnelsFragmentEmpty(t *testing.T) {
	h := newTestHandler(t)
	sc := doSignup(t, h, "empty@b.example.com", "pw12345678")

	req := httptest.NewRequest("GET", "/tunnels/status", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "No live tunnels")
}

// getCSRF fetches path (optionally as the signed-in user) and extracts both
// the csrf cookie and the hidden-input token from the response body.
func getCSRF(t *testing.T, h http.Handler, sc *http.Cookie, path string) (tokenValue string, csrfCookie *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if sc != nil {
		req.AddCookie(sc)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()
	const marker = `name="gorilla.csrf.Token" value="`
	idx := strings.Index(body, marker)
	if idx == -1 {
		t.Fatalf("csrf token not found in body from %s (status=%d)", path, w.Code)
	}
	rest := body[idx+len(marker):]
	end := strings.IndexByte(rest, '"')
	if end == -1 {
		t.Fatalf("csrf token unterminated")
	}
	tokenValue = rest[:end]
	for _, c := range w.Result().Cookies() {
		if c.Name == "_gorilla_csrf" {
			csrfCookie = c
		}
	}
	if csrfCookie == nil {
		t.Fatalf("csrf cookie not set by GET %s", path)
	}
	return
}

// postForm builds a POST with both the session (if any) + csrf cookie and the
// csrf form field filled in. It comes from httptest's default peer address
// (192.0.2.1).
func postForm(t *testing.T, h http.Handler, sc *http.Cookie, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return postFormFrom(t, h, sc, path, form, "")
}

// postFormFrom is postForm from the peer address peer ("" keeps httptest's
// default). The options run on the POST request before it is served. It
// returns after the mails the request queued have been handed to the mailer.
func postFormFrom(t *testing.T, h http.Handler, sc *http.Cookie, path string, form url.Values, peer string, opts ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := newFormPost(t, h, sc, path, form, peer, opts...)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	drainMail(t, h)
	return w
}

// drainMail waits until the background sender of h has handed every queued
// mail to the mailer (or dropped it). Handlers do not wait for mail; tests
// that look at the mailer call this first. It fails the test when the queue
// does not drain within drainLimit.
func drainMail(t testing.TB, h http.Handler) {
	t.Helper()
	fh, ok := h.(*frontendHandler)
	if !ok || fh.mails == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		fh.mails.wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(drainLimit):
		t.Fatalf("the mail queue did not drain within %v", drainLimit)
	}
}

// drainLimit bounds drainMail and the Close at cleanup. It only ends a test
// that went wrong; the queue normally drains at once.
const drainLimit = 10 * time.Second

// closeAtCleanup stops the mail sender of h when the test ends.
func closeAtCleanup(t testing.TB, h http.Handler) {
	t.Helper()
	fh, ok := h.(*frontendHandler)
	if !ok {
		return
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), drainLimit)
		defer cancel()
		if err := fh.Close(ctx); err != nil {
			t.Errorf("close the mail sender: %v", err)
		}
	})
}

// newFormPost builds the request of postFormFrom without serving it.
func newFormPost(t *testing.T, h http.Handler, sc *http.Cookie, path string, form url.Values, peer string, opts ...func(*http.Request)) *http.Request {
	t.Helper()
	token, csrfCookie := getCSRF(t, h, sc, "/login")
	if sc != nil {
		// When authenticated, prefer fetching the token off a page the user
		// can actually see so the cookie matches the session scope. /login
		// works fine too since csrf is per-session, not per-user.
		token, csrfCookie = getCSRF(t, h, sc, "/dashboard")
	}
	if form == nil {
		form = url.Values{}
	}
	form.Set("gorilla.csrf.Token", token)

	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if peer != "" {
		req.RemoteAddr = peer
	}
	req.AddCookie(csrfCookie)
	if sc != nil {
		req.AddCookie(sc)
	}
	for _, o := range opts {
		o(req)
	}
	return req
}

// testPeerSeq numbers the peer addresses nextPeer hands out.
var testPeerSeq atomic.Uint32

// nextPeer returns a peer address that no earlier call in this test binary
// returned, so that tests which sign up several users do not share one
// sign-up rate limit.
func nextPeer() string {
	n := testPeerSeq.Add(1)
	return fmt.Sprintf("10.%d.%d.%d:40000", byte(n>>16), byte(n>>8), byte(n))
}

// postHTMX issues an HTMX-style POST (no form body needed) that passes the
// CSRF token via the X-CSRF-Token header, matching the hx-headers wiring.
func postHTMX(t *testing.T, h http.Handler, sc *http.Cookie, refererPath, path string) *httptest.ResponseRecorder {
	t.Helper()
	return postHTMXFrom(t, h, sc, refererPath, path, "")
}

// postHTMXFrom is postHTMX from the peer address peer ("" keeps httptest's
// default).
func postHTMXFrom(t *testing.T, h http.Handler, sc *http.Cookie, refererPath, path, peer string) *httptest.ResponseRecorder {
	t.Helper()
	token, csrfCookie := getCSRF(t, h, sc, refererPath)
	req := httptest.NewRequest("POST", path, nil)
	if peer != "" {
		req.RemoteAddr = peer
	}
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	if sc != nil {
		req.AddCookie(sc)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	drainMail(t, h)
	return w
}

// doSignup signs up a new account and logs in with it; it returns the
// session cookie of the login. (Signup itself does not log in: its answer
// must be the same for an address that is already taken.)
func doSignup(t *testing.T, h http.Handler, email, password string) *http.Cookie {
	t.Helper()
	peer := nextPeer()
	form := url.Values{"email": {email}, "password": {password}}
	w := postFormFrom(t, h, nil, "/signup", form, peer)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("signup failed; status=%d body=%q", w.Code, w.Body.String())
	}
	w = postFormFrom(t, h, nil, "/login", url.Values{"email": {email}, "password": {password}}, peer)
	for _, c := range w.Result().Cookies() {
		if c.Name == "tunneld_session" {
			return c
		}
	}
	t.Fatalf("login after signup did not set session cookie; status=%d body=%q", w.Code, w.Body.String())
	return nil
}

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	return New(Options{
		Domain:       "tunnel.localhost",
		Users:        users.NewService(pool),
		Tokens:       tokens.NewService(pool),
		Reservations: reservations.NewService(pool),
		Sessions:     sessions.NewService(pool),
		Registry:     registry.New(),
		CSRFKey:      testCSRFKey,
		CSRFSecure:   false,
	})
}

func TestStaticCSSServed(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/_static/app.css", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/css")
}

func TestRootRedirectsToLoginWhenUnauthenticated(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestDashboardRedirectsUnauthenticated(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "/login")
}

func TestSecurityHeadersPresent(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.NotEmpty(t, w.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	csp := w.Header().Get("Content-Security-Policy")
	assert.NotEmpty(t, csp)
	// CSP must include a per-request nonce.
	assert.Contains(t, csp, "'nonce-")
}

// Sanity: the embed didn't drop files.
func TestStubPagesAreHTML(t *testing.T) {
	h := newTestHandler(t)
	for _, path := range []string{"/signup", "/login"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, path)
		assert.Contains(t, strings.ToLower(w.Header().Get("Content-Type")), "text/html", path)
	}
}

func TestSignupCreatesUserAndSendsToLogin(t *testing.T) {
	h := newTestHandler(t)

	w := postForm(t, h, nil, "/signup", url.Values{"email": {"a@b.example.com"}, "password": {"hunter222"}})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login?signup=1", w.Header().Get("Location"))
	for _, c := range w.Result().Cookies() {
		assert.NotEqual(t, "tunneld_session", c.Name, "signup does not log in")
	}

	// The login page explains what happened; the account works.
	req := httptest.NewRequest("GET", "/login?signup=1", nil)
	lw := httptest.NewRecorder()
	h.ServeHTTP(lw, req)
	require.Equal(t, http.StatusOK, lw.Code)
	assert.Contains(t, lw.Body.String(), "log in")

	w = postForm(t, h, nil, "/login", url.Values{"email": {"a@b.example.com"}, "password": {"hunter222"}})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/dashboard", w.Header().Get("Location"))
}

func TestSignupWithTakenEmailLooksLikeSuccess(t *testing.T) {
	h := newTestHandler(t)
	form := url.Values{"email": {"dup@b.example.com"}, "password": {"hunter222"}}
	w1 := postForm(t, h, nil, "/signup", form)
	require.Equal(t, http.StatusSeeOther, w1.Code)

	w2 := postForm(t, h, nil, "/signup", url.Values{"email": {"dup@b.example.com"}, "password": {"other-pw1"}})
	require.Equal(t, http.StatusSeeOther, w2.Code)
	assert.Equal(t, w1.Header().Get("Location"), w2.Header().Get("Location"))
	assert.NotContains(t, w2.Body.String(), "already registered")

	// The original password still works, the second one does not.
	w := postForm(t, h, nil, "/login", url.Values{"email": {"dup@b.example.com"}, "password": {"other-pw1"}})
	require.Equal(t, http.StatusUnauthorized, w.Code)
	w = postForm(t, h, nil, "/login", url.Values{"email": {"dup@b.example.com"}, "password": {"hunter222"}})
	require.Equal(t, http.StatusSeeOther, w.Code)
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	h := newTestHandler(t)
	w := postForm(t, h, nil, "/signup", url.Values{"email": {"log@b.example.com"}, "password": {"correct1"}})
	require.Equal(t, http.StatusSeeOther, w.Code)

	w = postForm(t, h, nil, "/login", url.Values{"email": {"log@b.example.com"}, "password": {"wrong"}})
	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid email or password")
}

func TestLoginBlocksDisabledUser(t *testing.T) {
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)

	userSvc := users.NewService(pool)
	h := New(Options{
		Domain:       "tunnel.localhost",
		Users:        userSvc,
		Tokens:       tokens.NewService(pool),
		Reservations: reservations.NewService(pool),
		Sessions:     sessions.NewService(pool),
		Registry:     registry.New(),
		CSRFKey:      testCSRFKey,
		CSRFSecure:   false,
	})

	// Signup succeeds.
	_ = doSignup(t, h, "disabled@b.example.com", "pw12345678")

	// Disable the user directly via the service.
	u, err := userSvc.FindByEmail(context.Background(), "disabled@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Disable(context.Background(), nil, u.ID))

	// Login with correct credentials should still return the generic error.
	w := postForm(t, h, nil, "/login", url.Values{"email": {"disabled@b.example.com"}, "password": {"pw12345678"}})
	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid email or password")
	// Must not set a session cookie.
	for _, c := range w.Result().Cookies() {
		assert.NotEqual(t, "tunneld_session", c.Name, "session cookie must not be set for disabled user")
	}
}

func TestDashboardShowsUserInfo(t *testing.T) {
	h := newTestHandler(t)
	sc := doSignup(t, h, "dash@b.example.com", "pw12345678")

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "dash@b.example.com")
	assert.Contains(t, body, "Active tokens")
	assert.Contains(t, body, "Reservations")
	assert.Contains(t, body, "Live tunnels")
	assert.Contains(t, body, "Create a token to start tunneling.")
}

func TestLogoutClearsCookie(t *testing.T) {
	h := newTestHandler(t)
	sc := doSignup(t, h, "out@b.example.com", "pw12345678")

	w := postForm(t, h, sc, "/logout", nil)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))

	var cleared *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "tunneld_session" {
			cleared = c
		}
	}
	require.NotNil(t, cleared)
	assert.True(t, cleared.MaxAge < 0)
}

func TestTokensCreateAndRevoke(t *testing.T) {
	h := newTestHandler(t)
	sc := doSignup(t, h, "tok@b.example.com", "pw12345678")

	// GET /tokens → 200, empty state.
	req := httptest.NewRequest("GET", "/tokens", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "No tokens yet")

	// POST /tokens — create.
	w = postForm(t, h, sc, "/tokens", url.Values{"name": {"Laptop"}})
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "twbl_")
	assert.Contains(t, body, "Laptop")

	// GET /tokens to find the ID from the revoke href.
	req = httptest.NewRequest("GET", "/tokens", nil)
	req.AddCookie(sc)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body = w.Body.String()
	start := strings.Index(body, "/tokens/")
	require.NotEqual(t, -1, start)
	end := strings.Index(body[start:], "/revoke")
	require.NotEqual(t, -1, end)
	path := body[start : start+end+len("/revoke")]

	// Revoke via HTMX-style POST with X-CSRF-Token header.
	w = postHTMX(t, h, sc, "/tokens", path)
	require.Equal(t, http.StatusOK, w.Code)

	// GET /tokens — revoked one should no longer appear.
	req = httptest.NewRequest("GET", "/tokens", nil)
	req.AddCookie(sc)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Contains(t, w.Body.String(), "No tokens yet")
}

func TestReservationsCreateAndRelease(t *testing.T) {
	h := newTestHandler(t)
	sc := doSignup(t, h, "res@b.example.com", "pw12345678")

	// GET page — empty.
	req := httptest.NewRequest("GET", "/reservations", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "No reservations yet")

	// Reserve "myapp".
	w = postForm(t, h, sc, "/reservations", url.Values{"subdomain": {"myapp"}})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "myapp.tunnel.localhost")

	// System-reserved. Field errors answer 422, the status htmx is set up
	// to swap.
	w = postForm(t, h, sc, "/reservations", url.Values{"subdomain": {"admin"}})
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "system use")

	// Regex fail.
	w = postForm(t, h, sc, "/reservations", url.Values{"subdomain": {"Has_Underscore"}})
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Already reserved.
	w = postForm(t, h, sc, "/reservations", url.Values{"subdomain": {"myapp"}})
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "already reserved")

	// Release "myapp" via HTMX-style POST.
	w = postHTMX(t, h, sc, "/reservations", "/reservations/myapp/release")
	require.Equal(t, http.StatusOK, w.Code)

	// Empty list again.
	req = httptest.NewRequest("GET", "/reservations", nil)
	req.AddCookie(sc)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Contains(t, w.Body.String(), "No reservations yet")
}

func TestReservationCreateRejectsTwoCharSubdomain(t *testing.T) {
	h := newTestHandler(t)
	sc := doSignup(t, h, "tc@b.example.com", "pw12345678")

	w := postForm(t, h, sc, "/reservations", url.Values{"subdomain": {"ab"}})
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestReservationsReleaseForbiddenForOtherUser(t *testing.T) {
	h := newTestHandler(t)
	scA := doSignup(t, h, "ra@b.example.com", "pw12345678")
	scB := doSignup(t, h, "rb@b.example.com", "pw12345678")

	// A reserves.
	postForm(t, h, scA, "/reservations", url.Values{"subdomain": {"ashared"}})

	// B tries to release via HTMX.
	w := postHTMX(t, h, scB, "/reservations", "/reservations/ashared/release")
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestSettingsShowsEmail(t *testing.T) {
	h := newTestHandler(t)
	sc := doSignup(t, h, "set@b.example.com", "pw12345678")

	req := httptest.NewRequest("GET", "/settings", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "set@b.example.com")
	assert.Contains(t, w.Body.String(), "Change password")
}

func TestChangePasswordHappyPath(t *testing.T) {
	h := newTestHandler(t)
	scOther := doSignup(t, h, "chg2@b.example.com", "pw12345678")
	// A second login of the same account: the browser the change comes from.
	w := postFormFrom(t, h, nil, "/login", url.Values{"email": {"chg2@b.example.com"}, "password": {"pw12345678"}}, nextPeer())
	scCurrent := findCookie(w, "tunneld_session")
	require.NotNil(t, scCurrent)

	w = postForm(t, h, scCurrent, "/settings/password", url.Values{
		"current": {"pw12345678"},
		"new":     {"newer45678"},
		"confirm": {"newer45678"},
	})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/settings?changed=1", w.Header().Get("Location"))
	scNew := findCookie(w, "tunneld_session")
	require.NotNil(t, scNew, "the browser gets a new session")
	require.NotEqual(t, scCurrent.Value, scNew.Value)

	get := func(sc *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/settings", nil)
		req.AddCookie(sc)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	// The new session works ...
	require.Equal(t, http.StatusOK, get(scNew).Code)
	// ... every earlier session of the account has ended, the one the
	// change came from included.
	for name, sc := range map[string]*http.Cookie{"current": scCurrent, "other": scOther} {
		w = get(sc)
		require.Equal(t, http.StatusSeeOther, w.Code, name)
		assert.Equal(t, "/login", w.Header().Get("Location"), name)
	}

	// Logging in with the new password works.
	w = postForm(t, h, nil, "/login", url.Values{"email": {"chg2@b.example.com"}, "password": {"newer45678"}})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/dashboard", w.Header().Get("Location"))

	// Logging in with the old password fails.
	w = postForm(t, h, nil, "/login", url.Values{"email": {"chg2@b.example.com"}, "password": {"pw12345678"}})
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestChangePasswordRejectsWrongCurrent(t *testing.T) {
	h := newTestHandler(t)
	sc := doSignup(t, h, "wrong@b.example.com", "correctpw1")

	w := postForm(t, h, sc, "/settings/password", url.Values{
		"current": {"wrongpw"},
		"new":     {"newpass1234"},
		"confirm": {"newpass1234"},
	})
	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "current password is incorrect")
}

func TestChangePasswordRejectsMismatch(t *testing.T) {
	h := newTestHandler(t)
	sc := doSignup(t, h, "mm@b.example.com", "pw12345678")

	w := postForm(t, h, sc, "/settings/password", url.Values{
		"current": {"pw12345678"},
		"new":     {"newpass1234"},
		"confirm": {"differnt1234"},
	})
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "do not match")
}

func TestTokensRevokeOfOtherUsersTokenIsNotFound(t *testing.T) {
	h := newTestHandler(t)
	scA := doSignup(t, h, "a-tok@b.example.com", "pw12345678")
	scB := doSignup(t, h, "b-tok@b.example.com", "pw12345678")

	// User A creates a token.
	postForm(t, h, scA, "/tokens", url.Values{"name": {"A-laptop"}})

	// Find the ID via A's /tokens page.
	req := httptest.NewRequest("GET", "/tokens", nil)
	req.AddCookie(scA)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()
	start := strings.Index(body, "/tokens/")
	require.NotEqual(t, -1, start)
	end := strings.Index(body[start:], "/revoke")
	require.NotEqual(t, -1, end)
	path := body[start : start+end+len("/revoke")]

	// User B tries to revoke → 404, the same answer as for a token that
	// does not exist (the revoke is bound to the owner in the database).
	w = postHTMX(t, h, scB, "/tokens", path)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestSignupSendsVerificationEmail(t *testing.T) {
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)

	userSvc := users.NewService(pool)
	verSvc := verifications.NewService(pool, userSvc)
	tm := mail.NewTestMailer()

	h := New(Options{
		Domain:        "tunnel.localhost",
		Users:         userSvc,
		Tokens:        tokens.NewService(pool),
		Reservations:  reservations.NewService(pool),
		Sessions:      sessions.NewService(pool),
		Registry:      registry.New(),
		CSRFKey:       testCSRFKey,
		CSRFSecure:    false,
		Mailer:        tm,
		Verifications: verSvc,
		PublicBaseURL: "https://app.tunnel.localhost",
	})
	closeAtCleanup(t, h)

	sc := doSignup(t, h, "v@example.com", "pw12345678")
	_ = sc

	// TestMailer captured exactly one message.
	sent := tm.Sent()
	require.Len(t, sent, 1)
	assert.Equal(t, "v@example.com", sent[0].To)
	assert.Contains(t, sent[0].Subject, "Verify")
	assert.Contains(t, sent[0].HTMLBody, "https://app.tunnel.localhost/verify?token=")
	assert.Contains(t, sent[0].TextBody, "verify your email")
}

// newTestHandlerWithMail builds a frontend handler with a live mailer +
// verifications service wired up. Returns the handler plus the backing
// services so tests can inspect sent mail and consume tokens directly.
func newTestHandlerWithMail(t *testing.T) (http.Handler, *users.Service, *verifications.Service, *mail.TestMailer) {
	t.Helper()
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)

	userSvc := users.NewService(pool)
	sessSvc := sessions.NewService(pool)
	verSvc := verifications.NewService(pool, userSvc)
	pwrSvc := passwordreset.NewService(pool, userSvc, sessSvc)
	tm := mail.NewTestMailer()

	h := New(Options{
		Domain:        "tunnel.localhost",
		Users:         userSvc,
		Tokens:        tokens.NewService(pool),
		Reservations:  reservations.NewService(pool),
		Sessions:      sessSvc,
		Registry:      registry.New(),
		CSRFKey:       testCSRFKey,
		CSRFSecure:    false,
		Mailer:        tm,
		Verifications: verSvc,
		PasswordReset: pwrSvc,
		PublicBaseURL: "https://app.tunnel.localhost",
	})
	closeAtCleanup(t, h)
	return h, userSvc, verSvc, tm
}

// extractResetToken pulls the raw token off a captured password-reset email.
func extractResetToken(t *testing.T, body string) string {
	t.Helper()
	const marker = "/reset?token="
	i := strings.Index(body, marker)
	if i == -1 {
		t.Fatalf("reset token not found in body: %q", body)
	}
	rest := body[i+len(marker):]
	end := strings.IndexAny(rest, " \r\n\"<'")
	if end == -1 {
		end = len(rest)
	}
	raw := strings.TrimSpace(rest[:end])
	if raw == "" {
		t.Fatalf("empty reset token extracted from %q", body)
	}
	return raw
}

func TestForgotPasswordRendersForm(t *testing.T) {
	h, _, _, _ := newTestHandlerWithMail(t)
	req := httptest.NewRequest("GET", "/forgot-password", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Enter your email")
}

func TestForgotPasswordKnownEmailSendsEmail(t *testing.T) {
	h, _, _, tm := newTestHandlerWithMail(t)
	_ = doSignup(t, h, "reset@example.com", "initialpw1")
	tm.Reset() // clear the verify email captured at signup

	w := postForm(t, h, nil, "/forgot-password", url.Values{"email": {"reset@example.com"}})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "If an account with that email exists")

	sent := tm.Sent()
	require.Len(t, sent, 1)
	assert.Equal(t, "reset@example.com", sent[0].To)
	assert.Contains(t, sent[0].Subject, "Reset")
	assert.Contains(t, sent[0].HTMLBody, "/reset?token=")
}

func TestForgotPasswordUnknownEmailRespondsGeneric(t *testing.T) {
	h, _, _, tm := newTestHandlerWithMail(t)
	w := postForm(t, h, nil, "/forgot-password", url.Values{"email": {"nobody@example.com"}})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "If an account with that email exists")

	// No email sent for an unknown address.
	assert.Len(t, tm.Sent(), 0)
}

func TestResetFlowHappyPath(t *testing.T) {
	h, userSvc, _, tm := newTestHandlerWithMail(t)
	_ = doSignup(t, h, "flow@example.com", "initialpw1")
	tm.Reset()

	// Request reset.
	w := postForm(t, h, nil, "/forgot-password", url.Values{"email": {"flow@example.com"}})
	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, tm.Sent(), 1)

	token := extractResetToken(t, tm.Sent()[0].TextBody)

	// Submit new password.
	w = postForm(t, h, nil, "/reset", url.Values{
		"token":   {token},
		"new":     {"newerpw5678"},
		"confirm": {"newerpw5678"},
	})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login?reset=1", w.Header().Get("Location"))

	// Old password no longer works.
	u, err := userSvc.FindByEmail(context.Background(), "flow@example.com")
	require.NoError(t, err)
	ok, err := userSvc.VerifyPassword(context.Background(), u.ID, "initialpw1")
	require.NoError(t, err)
	assert.False(t, ok)

	// New password works.
	ok, err = userSvc.VerifyPassword(context.Background(), u.ID, "newerpw5678")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestResetRejectsMismatch(t *testing.T) {
	h, _, _, tm := newTestHandlerWithMail(t)
	_ = doSignup(t, h, "mm-reset@example.com", "initialpw1")
	tm.Reset()

	w := postForm(t, h, nil, "/forgot-password", url.Values{"email": {"mm-reset@example.com"}})
	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, tm.Sent(), 1)
	token := extractResetToken(t, tm.Sent()[0].TextBody)

	w = postForm(t, h, nil, "/reset", url.Values{
		"token":   {token},
		"new":     {"first1234"},
		"confirm": {"second5678"},
	})
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "do not match")
}

func TestLoginShowsResetSuccessBanner(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/login?reset=1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Password reset")
	assert.Contains(t, w.Body.String(), "/forgot-password")
}

// extractVerifyToken pulls the raw token off a captured verification email
// (looks in HTMLBody first, then TextBody).
func extractVerifyToken(t *testing.T, msg mail.Message) string {
	t.Helper()
	const marker = "/verify?token="
	bodies := []string{msg.HTMLBody, msg.TextBody}
	for _, body := range bodies {
		i := strings.Index(body, marker)
		if i == -1 {
			continue
		}
		rest := body[i+len(marker):]
		end := strings.IndexAny(rest, " \r\n\"<'")
		if end == -1 {
			end = len(rest)
		}
		raw := strings.TrimSpace(rest[:end])
		if raw != "" {
			return raw
		}
	}
	t.Fatalf("verify token not found in mail body: html=%q text=%q", msg.HTMLBody, msg.TextBody)
	return ""
}

// confirmVerification opens the verification link and submits the form of
// its confirmation page, as a user does.
func confirmVerification(t *testing.T, h http.Handler, raw string) *httptest.ResponseRecorder {
	t.Helper()
	return confirmVerificationFrom(t, h, raw, "")
}

// confirmVerificationFrom is confirmVerification from the peer address peer
// ("" keeps httptest's default).
func confirmVerificationFrom(t *testing.T, h http.Handler, raw, peer string) *httptest.ResponseRecorder {
	t.Helper()
	token, csrfCookie := getCSRF(t, h, nil, "/verify?token="+url.QueryEscape(raw))
	form := url.Values{"token": {raw}, "gorilla.csrf.Token": {token}}
	req := httptest.NewRequest("POST", "/verify", strings.NewReader(form.Encode()))
	if peer != "" {
		req.RemoteAddr = peer
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestVerifyEndpointFlipsFlag(t *testing.T) {
	h, userSvc, _, tm := newTestHandlerWithMail(t)

	doSignup(t, h, "v8@example.com", "pw12345678")
	sent := tm.Sent()
	require.Len(t, sent, 1)
	raw := extractVerifyToken(t, sent[0])

	w := confirmVerification(t, h, raw)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/dashboard?verified=1", w.Header().Get("Location"))

	u, err := userSvc.FindByEmail(context.Background(), "v8@example.com")
	require.NoError(t, err)
	assert.True(t, u.EmailVerifiedAt.Valid)
}

func TestVerifyEndpointShowsErrorOnBadToken(t *testing.T) {
	h, _, _, _ := newTestHandlerWithMail(t)
	req := httptest.NewRequest("GET", "/verify?token=not-a-real-token", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "invalid or has expired")
}

func TestTokensCreateBlockedWhenUnverified(t *testing.T) {
	h, _, _, _ := newTestHandlerWithMail(t)
	sc := doSignup(t, h, "block@example.com", "pw12345678")

	w := postForm(t, h, sc, "/tokens", url.Values{"name": {"Laptop"}})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/dashboard?needs_verification=1", w.Header().Get("Location"))
}

func TestReservationsCreateBlockedWhenUnverified(t *testing.T) {
	h, _, _, _ := newTestHandlerWithMail(t)
	sc := doSignup(t, h, "block-res@example.com", "pw12345678")

	w := postForm(t, h, sc, "/reservations", url.Values{"subdomain": {"myapp"}})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/dashboard?needs_verification=1", w.Header().Get("Location"))
}

func TestTokensCreateAllowedAfterVerify(t *testing.T) {
	h, _, _, tm := newTestHandlerWithMail(t)
	sc := doSignup(t, h, "ok@example.com", "pw12345678")

	// Consume the verification link.
	raw := extractVerifyToken(t, tm.Sent()[0])
	w := confirmVerification(t, h, raw)
	require.Equal(t, http.StatusSeeOther, w.Code)

	// POST /tokens now succeeds.
	w = postForm(t, h, sc, "/tokens", url.Values{"name": {"Laptop"}})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "twbl_")
}

func TestDashboardBannerWhenUnverified(t *testing.T) {
	h, _, _, _ := newTestHandlerWithMail(t)
	sc := doSignup(t, h, "banner@example.com", "pw12345678")

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "Please verify your email")
	assert.Contains(t, body, `action="/verify/resend"`)
}

func TestVerifyResendSendsNewEmail(t *testing.T) {
	h, _, _, tm := newTestHandlerWithMail(t)
	sc := doSignup(t, h, "resend@example.com", "pw12345678")
	require.Len(t, tm.Sent(), 1)

	w := postForm(t, h, sc, "/verify/resend", nil)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/dashboard?resend=ok", w.Header().Get("Location"))
	require.Len(t, tm.Sent(), 2)
	assert.Equal(t, "resend@example.com", tm.Sent()[1].To)
}

// TestPOSTWithoutCSRFTokenRejected verifies that the CSRF middleware is wired
// up correctly: a POST to /signup without any CSRF token or cookie must be
// rejected with 403 Forbidden.
func TestPOSTWithoutCSRFTokenRejected(t *testing.T) {
	h := newTestHandler(t)

	form := url.Values{"email": {"no-csrf@b.example.com"}, "password": {"pw12345678"}}
	req := httptest.NewRequest("POST", "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
}
