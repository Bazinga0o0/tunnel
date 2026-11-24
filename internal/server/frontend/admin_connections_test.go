package frontend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// fakeCloseableSession implements Session + Closer + UserIDer + ConnectedAter
// for admin-connections tests that need to verify Close is called on kill.
type fakeCloseableSession struct {
	id          string
	userID      int64
	connectedAt time.Time
	closed      bool
}

func (f *fakeCloseableSession) ID() string                  { return f.id }
func (f *fakeCloseableSession) UserIDValue() int64          { return f.userID }
func (f *fakeCloseableSession) ConnectedAtValue() time.Time { return f.connectedAt }
func (f *fakeCloseableSession) Close() error {
	f.closed = true
	return nil
}

// newAdminHandlerWithRegistry builds a handler backed by a real DB pool and
// the supplied registry, also returning the users service.
func newAdminHandlerWithRegistry(t *testing.T, reg *registry.Registry) (http.Handler, *users.Service) {
	t.Helper()
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	svc := users.NewService(pool)
	h := New(Options{
		Domain:       "tunnel.localhost",
		Users:        svc,
		Tokens:       tokens.NewService(pool),
		Reservations: reservations.NewService(pool),
		Sessions:     sessions.NewService(pool),
		Registry:     reg,
		CSRFKey:      testCSRFKey,
		CSRFSecure:   false,
	})
	return h, svc
}

// setupAdminWithRegistry signs up a user, promotes to admin, and returns the
// handler and session cookie.
func setupAdminWithRegistry(t *testing.T, reg *registry.Registry, email string) (http.Handler, *http.Cookie) {
	t.Helper()
	h, svc := newAdminHandlerWithRegistry(t, reg)
	sc := doSignup(t, h, email, "pw12345678")
	u, err := svc.FindByEmail(context.Background(), email)
	require.NoError(t, err)
	require.NoError(t, svc.Promote(context.Background(), u.ID))
	return h, sc
}

func TestAdminConnectionsPageRendersSkeletonHTML(t *testing.T) {
	reg := registry.New()
	h, sc := setupAdminWithRegistry(t, reg, "conn-page@b.example.com")

	req := httptest.NewRequest("GET", "/admin/connections", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "Live connections")
	// Page includes the HTMX polling div pointed at the status fragment.
	assert.Contains(t, body, "/admin/connections/status")
}

func TestAdminConnectionsStatusEmpty(t *testing.T) {
	reg := registry.New()
	h, sc := setupAdminWithRegistry(t, reg, "conn-empty@b.example.com")

	req := httptest.NewRequest("GET", "/admin/connections/status", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "No active tunnel connections right now")
}

func TestAdminConnectionsStatusListsSessions(t *testing.T) {
	reg := registry.New()
	h, sc := setupAdminWithRegistry(t, reg, "conn-list@b.example.com")

	sess := &fakeCloseableSession{
		id:          "sess-abc",
		userID:      1,
		connectedAt: time.Now().Add(-30 * time.Second),
	}
	require.NoError(t, reg.RegisterHTTP("myapp", sess))

	req := httptest.NewRequest("GET", "/admin/connections/status", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "myapp")
	assert.Contains(t, body, "http")
}

func TestAdminConnectionsStatusNonAdminForbidden(t *testing.T) {
	reg := registry.New()
	h, svc := newAdminHandlerWithRegistry(t, reg)
	sc := doSignup(t, h, "conn-nonadmin@b.example.com", "pw12345678")
	_ = svc // not promoted; should hit 404 from admin middleware

	req := httptest.NewRequest("GET", "/admin/connections/status", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}
