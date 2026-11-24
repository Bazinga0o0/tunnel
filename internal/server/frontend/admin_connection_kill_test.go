package frontend

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

func TestAdminConnectionKillUnknownSessionReturns404(t *testing.T) {
	reg := registry.New()
	h, sc := setupAdminWithRegistry(t, reg, "kill-notfound@b.example.com")

	token, csrfCookie := getCSRF(t, h, sc, "/admin/connections")
	req := httptest.NewRequest("POST", "/admin/connections/no-such-session/kill",
		strings.NewReader("gorilla.csrf.Token="+url.QueryEscape(token)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminConnectionKillClosesSessionAndReturns200(t *testing.T) {
	reg := registry.New()
	h, sc := setupAdminWithRegistry(t, reg, "kill-ok@b.example.com")

	sess := &fakeCloseableSession{id: "kill-target", userID: 99, connectedAt: time.Now()}
	require.NoError(t, reg.RegisterHTTP("victim", sess))

	token, csrfCookie := getCSRF(t, h, sc, "/admin/connections")
	req := httptest.NewRequest("POST", "/admin/connections/kill-target/kill",
		strings.NewReader("gorilla.csrf.Token="+url.QueryEscape(token)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, sess.closed, "Close() should have been called on the killed session")

	// Session is no longer in the registry.
	_, ok := reg.LookupHTTP("victim")
	assert.False(t, ok)

	// Subsequent kill of the same (now-removed) session returns 404.
	req2 := httptest.NewRequest("POST", "/admin/connections/kill-target/kill",
		strings.NewReader("gorilla.csrf.Token="+url.QueryEscape(token)))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(csrfCookie)
	req2.AddCookie(sc)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusNotFound, w2.Code)
}

func TestAdminConnectionKillRemovesSessionFromStatusFragment(t *testing.T) {
	reg := registry.New()
	h, sc := setupAdminWithRegistry(t, reg, "kill-fragment@b.example.com")

	sess := &fakeCloseableSession{id: "frag-victim", userID: 42, connectedAt: time.Now()}
	require.NoError(t, reg.RegisterHTTP("fragapp", sess))

	// Confirm it shows up in the status fragment before kill.
	req := httptest.NewRequest("GET", "/admin/connections/status", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "fragapp")

	// Kill it.
	token, csrfCookie := getCSRF(t, h, sc, "/admin/connections")
	killReq := httptest.NewRequest("POST", "/admin/connections/frag-victim/kill",
		strings.NewReader("gorilla.csrf.Token="+url.QueryEscape(token)))
	killReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	killReq.AddCookie(csrfCookie)
	killReq.AddCookie(sc)
	killW := httptest.NewRecorder()
	h.ServeHTTP(killW, killReq)
	require.Equal(t, http.StatusOK, killW.Code)

	// Fragment no longer shows it.
	req2 := httptest.NewRequest("GET", "/admin/connections/status", nil)
	req2.AddCookie(sc)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)
	assert.NotContains(t, w2.Body.String(), "fragapp")
}
