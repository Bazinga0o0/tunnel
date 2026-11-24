package frontend

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// secureBase is the origin of the web UI in the tests that run with
// CSRFSecure: the requests carry an https URL, so httptest marks them as TLS
// requests and sets Host to app.tunnel.localhost.
const secureBase = "https://app.tunnel.localhost"

// newBareHandler builds a handler without any service. It is enough for
// everything that is decided before a handler runs (middleware) and for the
// pages that need no service (login, signup, forgot-password, logout without
// a session).
func newBareHandler(t *testing.T, mutate func(*Options)) http.Handler {
	t.Helper()
	opts := Options{Domain: "tunnel.localhost", CSRFKey: testCSRFKey}
	if mutate != nil {
		mutate(&opts)
	}
	return New(opts)
}

func secureMode(o *Options) { o.CSRFSecure = true }

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func findCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// csrfFrom fetches url and returns the form token of the page and the CSRF
// cookie with the given name.
func csrfFrom(t *testing.T, h http.Handler, target, cookieName string) (string, *http.Cookie) {
	t.Helper()
	w := serve(h, httptest.NewRequest(http.MethodGet, target, nil))
	body := w.Body.String()
	const marker = `name="gorilla.csrf.Token" value="`
	i := strings.Index(body, marker)
	require.NotEqual(t, -1, i, "csrf token missing on %s (status %d)", target, w.Code)
	rest := body[i+len(marker):]
	end := strings.IndexByte(rest, '"')
	require.NotEqual(t, -1, end)
	c := findCookie(w, cookieName)
	require.NotNil(t, c, "cookie %s not set by GET %s", cookieName, target)
	return rest[:end], c
}

func TestCSRFCookieNameFollowsCSRFSecure(t *testing.T) {
	t.Run("plain HTTP keeps the old name", func(t *testing.T) {
		w := serve(newBareHandler(t, nil), httptest.NewRequest(http.MethodGet, "/login", nil))
		require.Equal(t, http.StatusOK, w.Code)
		c := findCookie(w, "_gorilla_csrf")
		require.NotNil(t, c)
		assert.False(t, c.Secure)
		assert.Nil(t, findCookie(w, "__Host-tunneld_csrf"))
	})
	t.Run("CSRFSecure uses a __Host- cookie", func(t *testing.T) {
		w := serve(newBareHandler(t, secureMode), httptest.NewRequest(http.MethodGet, secureBase+"/login", nil))
		require.Equal(t, http.StatusOK, w.Code)
		c := findCookie(w, "__Host-tunneld_csrf")
		require.NotNil(t, c)
		// The browser only accepts a __Host- cookie with these attributes.
		assert.True(t, c.Secure)
		assert.Equal(t, "/", c.Path)
		assert.Empty(t, c.Domain)
		assert.True(t, c.HttpOnly)
		assert.Nil(t, findCookie(w, "_gorilla_csrf"))
	})
}

func TestSessionCookieNameFollowsCSRFSecure(t *testing.T) {
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	userSvc := users.NewService(pool)
	_, err := userSvc.Create(context.Background(), "secure@example.com", "pw12345678")
	require.NoError(t, err)

	h := New(Options{
		Domain:       "tunnel.localhost",
		Users:        userSvc,
		Tokens:       tokens.NewService(pool),
		Reservations: reservations.NewService(pool),
		Sessions:     sessions.NewService(pool),
		Registry:     registry.New(),
		CSRFKey:      testCSRFKey,
		CSRFSecure:   true,
	})

	token, csrfCookie := csrfFrom(t, h, secureBase+"/login", "__Host-tunneld_csrf")
	form := url.Values{"email": {"secure@example.com"}, "password": {"pw12345678"}, "gorilla.csrf.Token": {token}}
	req := httptest.NewRequest(http.MethodPost, secureBase+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", secureBase)
	req.AddCookie(csrfCookie)
	w := serve(h, req)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())

	sc := findCookie(w, "__Host-tunneld_session")
	require.NotNil(t, sc, "the session cookie carries the __Host- prefix")
	assert.True(t, sc.Secure)
	assert.Equal(t, "/", sc.Path)
	assert.Empty(t, sc.Domain)
	assert.True(t, sc.HttpOnly)
	assert.Nil(t, findCookie(w, "tunneld_session"))

	// The prefixed cookie is the one the middleware reads.
	req = httptest.NewRequest(http.MethodGet, secureBase+"/dashboard", nil)
	req.AddCookie(sc)
	w = serve(h, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "secure@example.com")

	// A cookie under the old name is not a session any more.
	req = httptest.NewRequest(http.MethodGet, secureBase+"/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "tunneld_session", Value: sc.Value})
	w = serve(h, req)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestDuplicateCookiesAreRejected(t *testing.T) {
	modes := []struct {
		name    string
		mutate  func(*Options)
		base    string
		session string
		csrf    string
		secure  bool
	}{
		{"plain HTTP", nil, "", "tunneld_session", "_gorilla_csrf", false},
		{"CSRFSecure", secureMode, secureBase, "__Host-tunneld_session", "__Host-tunneld_csrf", true},
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			h := newBareHandler(t, m.mutate)
			for _, dup := range []string{m.session, m.csrf} {
				for _, method := range []string{http.MethodGet, http.MethodPost} {
					req := httptest.NewRequest(method, m.base+"/login", nil)
					req.AddCookie(&http.Cookie{Name: dup, Value: "first"})
					req.AddCookie(&http.Cookie{Name: dup, Value: "second"})
					w := serve(h, req)
					require.Equal(t, http.StatusBadRequest, w.Code, "%s with two %s cookies", method, dup)
					for _, name := range []string{m.session, m.csrf} {
						c := findCookie(w, name)
						require.NotNil(t, c, "%s must be cleared", name)
						assert.Less(t, c.MaxAge, 0, "%s must be cleared", name)
						assert.Empty(t, c.Value)
						assert.Equal(t, "/", c.Path)
						assert.Equal(t, m.secure, c.Secure)
					}
				}
			}

			// The two cookies in separate Cookie headers count the same.
			req := httptest.NewRequest(http.MethodGet, m.base+"/login", nil)
			req.Header.Add("Cookie", m.session+"=first")
			req.Header.Add("Cookie", m.session+"=second")
			require.Equal(t, http.StatusBadRequest, serve(h, req).Code)

			// One cookie of each name is the normal case.
			req = httptest.NewRequest(http.MethodGet, m.base+"/login", nil)
			req.AddCookie(&http.Cookie{Name: m.session, Value: "one"})
			req.AddCookie(&http.Cookie{Name: m.csrf, Value: "two"})
			require.Equal(t, http.StatusOK, serve(h, req).Code)
		})
	}
}

func TestSecureModeExpiresTheOldCookieNames(t *testing.T) {
	h := newBareHandler(t, secureMode)
	req := httptest.NewRequest(http.MethodGet, secureBase+"/login", nil)
	req.AddCookie(&http.Cookie{Name: "tunneld_session", Value: "from-before-the-upgrade"})
	req.AddCookie(&http.Cookie{Name: "_gorilla_csrf", Value: "from-before-the-upgrade"})
	w := serve(h, req)
	require.Equal(t, http.StatusOK, w.Code, "the request itself goes on")
	for _, name := range []string{"tunneld_session", "_gorilla_csrf"} {
		c := findCookie(w, name)
		require.NotNil(t, c, "%s is expired", name)
		assert.Less(t, c.MaxAge, 0, name)
		assert.Empty(t, c.Value, name)
		assert.Equal(t, "/", c.Path, name)
		assert.True(t, c.Secure, name)
	}
	require.NotNil(t, findCookie(w, "__Host-tunneld_csrf"), "the current CSRF cookie is set as usual")

	// Without old cookies nothing is expired.
	w = serve(h, httptest.NewRequest(http.MethodGet, secureBase+"/login", nil))
	assert.Nil(t, findCookie(w, "tunneld_session"))
	assert.Nil(t, findCookie(w, "_gorilla_csrf"))

	// Over plain HTTP these are the current names: nothing expires them.
	plain := newBareHandler(t, nil)
	req = httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{Name: "tunneld_session", Value: "current"})
	w = serve(plain, req)
	assert.Nil(t, findCookie(w, "tunneld_session"))
}

func TestSecureModeRefusesForeignOrigin(t *testing.T) {
	h := newBareHandler(t, secureMode)
	token, csrfCookie := csrfFrom(t, h, secureBase+"/login", "__Host-tunneld_csrf")

	post := func(origin string) *httptest.ResponseRecorder {
		form := url.Values{"gorilla.csrf.Token": {token}}
		req := httptest.NewRequest(http.MethodPost, secureBase+"/logout", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		req.AddCookie(csrfCookie)
		return serve(h, req)
	}

	assert.Equal(t, http.StatusForbidden, post("https://evil.example").Code)
	// A tunnel on a subdomain is same-site, but not the same origin.
	assert.Equal(t, http.StatusForbidden, post("https://myapp.tunnel.localhost").Code)
	assert.Equal(t, http.StatusForbidden, post("http://app.tunnel.localhost").Code)
	// Control: the same request from the UI's own origin goes through.
	w := post(secureBase)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestSecurityHeadersAreComplete(t *testing.T) {
	const wantCSP = "default-src 'self'; style-src 'self'; script-src 'self' 'nonce-N'; img-src 'self' data:; " +
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
	nonce := regexp.MustCompile(`'nonce-[A-Za-z0-9+/]{22}'`)

	h := newBareHandler(t, nil)
	get := func(path string) *http.Request { return httptest.NewRequest(http.MethodGet, path, nil) }
	post := func(body string, contentType string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		return r
	}
	dupCookies := get("/login")
	dupCookies.AddCookie(&http.Cookie{Name: "tunneld_session", Value: "a"})
	dupCookies.AddCookie(&http.Cookie{Name: "tunneld_session", Value: "b"})

	cases := []struct {
		name   string
		req    *http.Request
		status int
	}{
		{"page", get("/login"), http.StatusOK},
		{"static file", get("/_static/app.css"), http.StatusOK},
		{"duplicate cookies", dupCookies, http.StatusBadRequest},
		{"unknown path", get("/no-such-page"), http.StatusNotFound},
		{"missing static file", get("/_static/missing.css"), http.StatusNotFound},
		{"body too large", post(strings.Repeat("a", 64<<10+1), "application/x-www-form-urlencoded"), http.StatusRequestEntityTooLarge},
		{"multipart", post("--x--\r\n", "multipart/form-data; boundary=x"), http.StatusUnsupportedMediaType},
	}
	for _, c := range cases {
		w := serve(h, c.req)
		require.Equal(t, c.status, w.Code, c.name)
		hd := w.Header()
		csp := hd.Get("Content-Security-Policy")
		assert.Regexp(t, nonce, csp, c.name)
		assert.Equal(t, wantCSP, nonce.ReplaceAllString(csp, "'nonce-N'"), c.name)
		assert.Equal(t, "same-origin", hd.Get("Cross-Origin-Opener-Policy"), c.name)
		assert.Equal(t, "same-origin", hd.Get("Cross-Origin-Resource-Policy"), c.name)
		assert.Equal(t, "nosniff", hd.Get("X-Content-Type-Options"), c.name)
		assert.Equal(t, "DENY", hd.Get("X-Frame-Options"), c.name)
		assert.Equal(t, "strict-origin-when-cross-origin", hd.Get("Referrer-Policy"), c.name)
		assert.Equal(t, "max-age=31536000; includeSubDomains", hd.Get("Strict-Transport-Security"), c.name)
	}
}

func TestAuthenticatedPagesAreNotCached(t *testing.T) {
	h := newTestHandler(t)
	sc := doSignup(t, h, "nocache@b.example.com", "pw12345678")
	for _, path := range []string{"/dashboard", "/tokens", "/reservations", "/settings", "/tunnels", "/tunnels/status"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(sc)
		w := serve(h, req)
		require.Equal(t, http.StatusOK, w.Code, path)
		assert.Contains(t, w.Header().Get("Cache-Control"), "no-store", path)
	}
	// The redirect for a visitor without a session is not cached either.
	w := serve(h, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Contains(t, w.Header().Get("Cache-Control"), "no-store")
}

func TestRequestBodyLimit(t *testing.T) {
	// formOf returns an urlencoded body of exactly n bytes.
	formOf := func(n int) string { return "email=" + strings.Repeat("a", n-len("email=")) }
	post := func(h http.Handler, body string, chunked bool, contentType string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		if chunked {
			// No Content-Length: the limit must hold while reading.
			req.ContentLength = -1
			req.Body = io.NopCloser(strings.NewReader(body))
		}
		req.Header.Set("Content-Type", contentType)
		return serve(h, req)
	}
	const urlencoded = "application/x-www-form-urlencoded"

	t.Run("64 KiB by default", func(t *testing.T) {
		h := newBareHandler(t, nil)
		w := post(h, formOf(64<<10+1), false, urlencoded)
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code, "over the limit with Content-Length")
		w = post(h, formOf(64<<10+1), true, urlencoded)
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code, "over the limit without Content-Length")
		// Exactly at the limit the request reaches the CSRF check (no token: 403).
		w = post(h, formOf(64<<10), false, urlencoded)
		assert.Equal(t, http.StatusForbidden, w.Code, "at the limit")
		w = post(h, formOf(64<<10), true, urlencoded)
		assert.Equal(t, http.StatusForbidden, w.Code, "at the limit without Content-Length")
	})
	t.Run("multipart bodies are refused", func(t *testing.T) {
		h := newBareHandler(t, nil)
		body := "--x\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\na\r\n--x--\r\n"
		for _, ct := range []string{"multipart/form-data; boundary=x", "Multipart/Mixed; boundary=x", " multipart/form-data"} {
			assert.Equal(t, http.StatusUnsupportedMediaType, post(h, body, false, ct).Code, ct)
		}
	})
	t.Run("MaxRequestBodyBytes sets the limit", func(t *testing.T) {
		h := newBareHandler(t, func(o *Options) { o.MaxRequestBodyBytes = 100 })
		assert.Equal(t, http.StatusRequestEntityTooLarge, post(h, formOf(101), false, urlencoded).Code)
		assert.Equal(t, http.StatusRequestEntityTooLarge, post(h, formOf(101), true, urlencoded).Code)
		assert.Equal(t, http.StatusForbidden, post(h, formOf(100), false, urlencoded).Code)
	})
	t.Run("a negative MaxRequestBodyBytes disables the size limit", func(t *testing.T) {
		h := newBareHandler(t, func(o *Options) { o.MaxRequestBodyBytes = -1 })
		assert.Equal(t, http.StatusForbidden, post(h, formOf(1<<20), false, urlencoded).Code)
		body := "--x\r\n\r\n--x--\r\n"
		assert.Equal(t, http.StatusUnsupportedMediaType, post(h, body, false, "multipart/form-data; boundary=x").Code,
			"multipart stays refused")
	})
}

func TestStaticServesFilesOnly(t *testing.T) {
	h := newBareHandler(t, nil)
	for _, path := range []string{"/_static/app.css", "/_static/htmx.min.js"} {
		w := serve(h, httptest.NewRequest(http.MethodGet, path, nil))
		assert.Equal(t, http.StatusOK, w.Code, path)
	}
	w := serve(h, httptest.NewRequest(http.MethodGet, "/_static/", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.NotContains(t, w.Body.String(), "app.css", "no directory listing")
	w = serve(h, httptest.NewRequest(http.MethodGet, "/_static/missing.css", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSessionLookupErrors(t *testing.T) {
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	h := New(Options{
		Domain:       "tunnel.localhost",
		Users:        users.NewService(pool),
		Tokens:       tokens.NewService(pool),
		Reservations: reservations.NewService(pool),
		Sessions:     sessions.NewService(pool),
		Registry:     registry.New(),
		CSRFKey:      testCSRFKey,
	})
	sc := doSignup(t, h, "lookup@b.example.com", "pw12345678")

	// A session that does not exist ends with a cleared cookie.
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "tunneld_session", Value: "no-such-session"})
	w := serve(h, req)
	require.Equal(t, http.StatusSeeOther, w.Code)
	c := findCookie(w, "tunneld_session")
	require.NotNil(t, c)
	assert.Less(t, c.MaxAge, 0)

	// With the database gone the lookup fails: 503, and the cookie stays.
	pool.Close()
	logged := captureLog(t)
	// Logging out still clears the cookie; the failed lookup is logged.
	w = postFormFrom(t, h, nil, "/logout", nil, "", func(r *http.Request) { r.AddCookie(sc) })
	require.Equal(t, http.StatusSeeOther, w.Code)
	c = findCookie(w, "tunneld_session")
	require.NotNil(t, c)
	assert.Less(t, c.MaxAge, 0)
	assert.Contains(t, logged.String(), "frontend: logout: look up session")

	for _, path := range []string{"/dashboard", "/"} {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(sc)
		w = serve(h, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code, path)
		assert.NotEmpty(t, w.Header().Get("Retry-After"), path)
		assert.Nil(t, findCookie(w, "tunneld_session"), "%s must leave the cookie alone", path)
		assert.NotContains(t, w.Body.String(), "closed", "%s must not show the internal error", path)
	}
}
