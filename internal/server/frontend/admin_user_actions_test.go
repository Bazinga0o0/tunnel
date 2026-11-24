package frontend

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminUserVerifyAction(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	adminSC := doSignup(t, h, "admin-verify-act@b.example.com", "pw12345678")
	admin, err := userSvc.FindByEmail(context.Background(), "admin-verify-act@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), admin.ID))

	target, err := userSvc.Create(context.Background(), "target-v@b.example.com", "pw12345678")
	require.NoError(t, err)

	w := postHTMX(t, h, adminSC, fmt.Sprintf("/admin/users/%d", target.ID),
		fmt.Sprintf("/admin/users/%d/verify", target.ID))

	// HTMX redirect (or 303 redirect back to detail page)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Contains(t, w.Header().Get("Location"), fmt.Sprintf("/admin/users/%d", target.ID))

	u, err := userSvc.FindByID(context.Background(), target.ID)
	require.NoError(t, err)
	assert.True(t, u.EmailVerifiedAt.Valid, "email should be verified after action")
}

func TestAdminUserDisableAction(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	adminSC := doSignup(t, h, "admin-dis-act@b.example.com", "pw12345678")
	admin, err := userSvc.FindByEmail(context.Background(), "admin-dis-act@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), admin.ID))

	target, err := userSvc.Create(context.Background(), "target-d@b.example.com", "pw12345678")
	require.NoError(t, err)

	w := postHTMX(t, h, adminSC, fmt.Sprintf("/admin/users/%d", target.ID),
		fmt.Sprintf("/admin/users/%d/disable", target.ID))

	require.Equal(t, http.StatusSeeOther, w.Code)

	u, err := userSvc.FindByID(context.Background(), target.ID)
	require.NoError(t, err)
	assert.True(t, u.DisabledAt.Valid, "user should be disabled after action")
}

func TestAdminUserDisableSelfBlocked(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	adminSC := doSignup(t, h, "admin-self-dis@b.example.com", "pw12345678")
	admin, err := userSvc.FindByEmail(context.Background(), "admin-self-dis@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), admin.ID))

	w := postHTMX(t, h, adminSC, fmt.Sprintf("/admin/users/%d", admin.ID),
		fmt.Sprintf("/admin/users/%d/disable", admin.ID))

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestAdminUserEnableAction(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	adminSC := doSignup(t, h, "admin-en-act@b.example.com", "pw12345678")
	admin, err := userSvc.FindByEmail(context.Background(), "admin-en-act@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), admin.ID))

	target, err := userSvc.Create(context.Background(), "target-en@b.example.com", "pw12345678")
	require.NoError(t, err)
	require.NoError(t, userSvc.Disable(context.Background(), nil, target.ID))

	w := postHTMX(t, h, adminSC, fmt.Sprintf("/admin/users/%d", target.ID),
		fmt.Sprintf("/admin/users/%d/enable", target.ID))

	require.Equal(t, http.StatusSeeOther, w.Code)

	u, err := userSvc.FindByID(context.Background(), target.ID)
	require.NoError(t, err)
	assert.False(t, u.DisabledAt.Valid, "user should be enabled after action")
}

func TestAdminUserPromoteAction(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	adminSC := doSignup(t, h, "admin-prom-act@b.example.com", "pw12345678")
	admin, err := userSvc.FindByEmail(context.Background(), "admin-prom-act@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), admin.ID))

	target, err := userSvc.Create(context.Background(), "target-prom@b.example.com", "pw12345678")
	require.NoError(t, err)
	// Promotion needs a verified address and the admin's current password.
	require.NoError(t, userSvc.MarkEmailVerified(context.Background(), target.ID))

	w := postForm(t, h, adminSC, fmt.Sprintf("/admin/users/%d/promote", target.ID),
		url.Values{"current_password": {"pw12345678"}})

	require.Equal(t, http.StatusSeeOther, w.Code)

	u, err := userSvc.FindByID(context.Background(), target.ID)
	require.NoError(t, err)
	assert.True(t, u.IsAdmin, "user should be admin after promote")
}

func TestAdminUserDemoteAction(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	adminSC := doSignup(t, h, "admin-dem-act@b.example.com", "pw12345678")
	admin, err := userSvc.FindByEmail(context.Background(), "admin-dem-act@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), admin.ID))

	target, err := userSvc.Create(context.Background(), "target-dem@b.example.com", "pw12345678")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), target.ID))

	w := postForm(t, h, adminSC, fmt.Sprintf("/admin/users/%d/demote", target.ID),
		url.Values{"current_password": {"pw12345678"}})

	require.Equal(t, http.StatusSeeOther, w.Code)

	u, err := userSvc.FindByID(context.Background(), target.ID)
	require.NoError(t, err)
	assert.False(t, u.IsAdmin, "user should not be admin after demote")
}

func TestAdminUserDemoteSelfBlocked(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	adminSC := doSignup(t, h, "admin-self-dem@b.example.com", "pw12345678")
	admin, err := userSvc.FindByEmail(context.Background(), "admin-self-dem@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), admin.ID))

	w := postHTMX(t, h, adminSC, fmt.Sprintf("/admin/users/%d", admin.ID),
		fmt.Sprintf("/admin/users/%d/demote", admin.ID))

	require.Equal(t, http.StatusForbidden, w.Code)
}

// The "last admin" refusal of demote and disable cannot be reached through
// the router; TestAdminDemoteSurfacesLastAdmin and
// TestAdminDisableSurfacesLastAdmin call the handlers directly.

func TestAdminUserResetPasswordAction(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	adminSC := doSignup(t, h, "admin-rp-act@b.example.com", "pw12345678")
	admin, err := userSvc.FindByEmail(context.Background(), "admin-rp-act@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), admin.ID))

	target, err := userSvc.Create(context.Background(), "target-rp@b.example.com", "pw12345678")
	require.NoError(t, err)

	w := postForm(t, h, adminSC, fmt.Sprintf("/admin/users/%d/reset-password", target.ID),
		url.Values{"new_password": {"newpassword12345"}, "current_password": {"pw12345678"}})

	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Contains(t, w.Header().Get("Location"), fmt.Sprintf("/admin/users/%d", target.ID))

	// New password should work.
	ok, err := userSvc.VerifyPassword(context.Background(), target.ID, "newpassword12345")
	require.NoError(t, err)
	assert.True(t, ok, "new password should work after reset")
}

func TestAdminUserResetPasswordTooShortRejected(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	adminSC := doSignup(t, h, "admin-rp-short@b.example.com", "pw12345678")
	admin, err := userSvc.FindByEmail(context.Background(), "admin-rp-short@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), admin.ID))

	target, err := userSvc.Create(context.Background(), "target-rp-short@b.example.com", "pw12345678")
	require.NoError(t, err)

	w := postForm(t, h, adminSC, fmt.Sprintf("/admin/users/%d/reset-password", target.ID),
		url.Values{"new_password": {"short"}})

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminUserResetPasswordSelfBlocked(t *testing.T) {
	h, userSvc := newTestHandlerWithUsers(t)
	adminSC := doSignup(t, h, "admin-rp-self@b.example.com", "pw12345678")
	admin, err := userSvc.FindByEmail(context.Background(), "admin-rp-self@b.example.com")
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), admin.ID))

	w := postForm(t, h, adminSC, fmt.Sprintf("/admin/users/%d/reset-password", admin.ID),
		url.Values{"new_password": {"newpassword12345"}})

	require.Equal(t, http.StatusForbidden, w.Code)
}
