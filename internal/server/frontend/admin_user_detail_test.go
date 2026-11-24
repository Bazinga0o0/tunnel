package frontend

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminUserDetailPageRendersEmail(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	sc := doSignup(t, h, "admin-det@b.example.com", "pw12345678")
	admin, err := userSvc.FindByEmail(context.Background(), "admin-det@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), admin.ID))

	target, err := userSvc.Create(context.Background(), "target@b.example.com", "pw12345678")
	require.NoError(t, err)

	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/users/%d", target.ID), nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "target@b.example.com")
	assert.Contains(t, body, "Profile")
	assert.Contains(t, body, "Activity")
	assert.Contains(t, body, "Actions")
}

// Next to the enable button the panel says that enabling brings back the
// account's API tokens that were not revoked.
func TestAdminUserDetailWarnsThatEnablingRevivesTokens(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	target := e.insertUser(t, "disabled@example.com", true)
	const hint = "API tokens of this account that were not revoked work again"

	w := e.get(t, e.adminCookie, "/admin/users/"+itoa(target))
	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), hint, "no hint while the account is enabled")

	require.NoError(t, e.users.Disable(ctx, nil, target))
	w = e.get(t, e.adminCookie, "/admin/users/"+itoa(target))
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	enable := strings.Index(body, ">Enable</button>")
	require.NotEqual(t, -1, enable, "the enable button")
	at := strings.Index(body, hint)
	require.NotEqual(t, -1, at, "the hint is shown for a disabled account")
	assert.Positive(t, at-enable, "the hint comes after the enable button")
	assert.Less(t, at-enable, 400, "the hint stands next to the enable button")
	assert.Contains(t, body, "Revoke all API tokens")
	assert.Contains(t, body, "tunneld admin list-tokens")
}

func TestAdminUserDetailMissingIDReturns404(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	sc := doSignup(t, h, "admin-det2@b.example.com", "pw12345678")
	admin, err := userSvc.FindByEmail(context.Background(), "admin-det2@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), admin.ID))

	req := httptest.NewRequest("GET", "/admin/users/999999", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminUserDetailNonAdminReturns404(t *testing.T) {
	h, _ := newTestHandlerWithUsers(t)
	sc := doSignup(t, h, "nonadmin-det@b.example.com", "pw12345678")

	req := httptest.NewRequest("GET", "/admin/users/1", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}
