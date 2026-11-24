package frontend

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// newTestHandlerWithUsers builds a full handler and also returns the users
// service so tests can promote/demote users directly.
func newTestHandlerWithUsers(t *testing.T) (http.Handler, *users.Service) {
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
		Registry:     registry.New(),
		CSRFKey:      testCSRFKey,
		CSRFSecure:   false,
	})
	return h, svc
}

func TestRequireAdminAllowsAdmin(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	sc := doSignup(t, h, "admin-ok@b.example.com", "pw12345678")

	u, err := userSvc.FindByEmail(context.Background(), "admin-ok@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), u.ID))

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Admin overview")
}

func TestRequireAdminRejectsNonAdmin(t *testing.T) {
	h, _ := newTestHandlerWithUsers(t)
	sc := doSignup(t, h, "nonadmin@b.example.com", "pw12345678")

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "not found")
}

func TestRequireAdminUnauthenticatedGetsNotFound(t *testing.T) {
	h, _ := newTestHandlerWithUsers(t)

	req := httptest.NewRequest("GET", "/admin", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	// No redirect to /login: /admin answers like a page that does not exist.
	require.Equal(t, http.StatusNotFound, w.Code)
	assert.Empty(t, w.Header().Get("Location"))
}
