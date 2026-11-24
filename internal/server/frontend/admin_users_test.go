package frontend

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupAdminUser signs up a user, promotes them to admin, and returns (handler,
// session cookie, userID).
func setupAdminUser(t *testing.T, email string) (http.Handler, *http.Cookie, int64) {
	t.Helper()
	h, userSvc := newTestHandlerWithUsers(t)
	sc := doSignup(t, h, email, "pw12345678")
	u, err := userSvc.FindByEmail(context.Background(), email)
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), u.ID))
	return h, sc, u.ID
}

func TestAdminUsersPageRendersAll(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	sc := doSignup(t, h, "admin-ul@b.example.com", "pw12345678")
	u, err := userSvc.FindByEmail(context.Background(), "admin-ul@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), u.ID))

	// Create a second user.
	_, err = userSvc.Create(context.Background(), "other@b.example.com", "pw12345678")
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/admin/users", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "admin-ul@b.example.com")
	assert.Contains(t, body, "other@b.example.com")
}

func TestAdminUsersPageSearchFilters(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	sc := doSignup(t, h, "admin-search@b.example.com", "pw12345678")
	u, err := userSvc.FindByEmail(context.Background(), "admin-search@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), u.ID))

	_, err = userSvc.Create(context.Background(), "alice@example.com", "pw12345678")
	require.NoError(t, err)
	_, err = userSvc.Create(context.Background(), "bob@example.com", "pw12345678")
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/admin/users?q=alice", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "alice@example.com")
	assert.NotContains(t, body, "bob@example.com")
}

func TestAdminUsersHTMXFragmentReturned(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	sc := doSignup(t, h, "admin-htmx@b.example.com", "pw12345678")
	u, err := userSvc.FindByEmail(context.Background(), "admin-htmx@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), u.ID))

	req := httptest.NewRequest("GET", "/admin/users?q=htmx", nil)
	req.Header.Set("HX-Request", "true")
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestAdminUsersPaginationWorks(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	sc := doSignup(t, h, "admin-page@b.example.com", "pw12345678")
	u, err := userSvc.FindByEmail(context.Background(), "admin-page@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), u.ID))

	// Create 25 additional users.
	for i := 0; i < 25; i++ {
		_, err = userSvc.Create(context.Background(), fmt.Sprintf("user%d@pag.example.com", i), "pw12345678")
		require.NoError(t, err)
	}

	req := httptest.NewRequest("GET", "/admin/users?page=2", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestAdminUsersNonAdminReturns404(t *testing.T) {
	h, _ := newTestHandlerWithUsers(t)
	sc := doSignup(t, h, "notadmin-ul@b.example.com", "pw12345678")

	req := httptest.NewRequest("GET", "/admin/users", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}
