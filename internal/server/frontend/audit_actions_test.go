package frontend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditRow is one row of audit_log as the tests read it.
type auditRow struct {
	Action   string
	UserID   *int64
	Metadata map[string]any
	IP       *netip.Addr
}

func (s *stack) auditRows(t *testing.T) []auditRow {
	t.Helper()
	rows, err := s.pool.Query(context.Background(), `SELECT action, user_id, metadata, ip FROM audit_log ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		var raw []byte
		require.NoError(t, rows.Scan(&r.Action, &r.UserID, &raw, &r.IP))
		if len(raw) > 0 {
			require.NoError(t, json.Unmarshal(raw, &r.Metadata))
		}
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

func TestEveryUserActionWritesOneAuditRow(t *testing.T) {
	s := newStack(t, withMail, withAudit)
	const peer = "203.0.113.50:4242"
	const email = "audited@example.com"

	// Sign up and verify the address.
	require.Equal(t, http.StatusSeeOther, s.post(t, peer, "/signup",
		url.Values{"email": {email}, "password": {"pw12345678"}}, nil).Code)
	uid := s.userID(t, email)
	require.Len(t, s.mailer.Sent(), 1)
	require.Equal(t, http.StatusSeeOther, confirmVerificationFrom(t, s.h, extractVerifyToken(t, s.mailer.Sent()[0]), peer).Code)

	// A failed and a successful login.
	require.Equal(t, http.StatusUnauthorized, s.login(t, peer, email, "wrong-password").Code)
	w := s.login(t, peer, email, "pw12345678")
	require.Equal(t, http.StatusSeeOther, w.Code)
	sc := findCookie(w, "tunneld_session")
	require.NotNil(t, sc)

	// A token, created and revoked.
	require.Equal(t, http.StatusOK, s.post(t, peer, "/tokens", url.Values{"name": {"laptop"}}, sc).Code)
	tokenID := s.tokenIDByName(t, uid, "laptop")
	require.Equal(t, http.StatusOK, postHTMXFrom(t, s.h, sc, "/tokens", fmt.Sprintf("/tokens/%d/revoke", tokenID), peer).Code)

	// A reservation, created and released.
	require.Equal(t, http.StatusOK, s.post(t, peer, "/reservations", url.Values{"subdomain": {"audited"}}, sc).Code)
	require.Equal(t, http.StatusOK, postHTMXFrom(t, s.h, sc, "/reservations", "/reservations/audited/release", peer).Code)

	// A password change, which hands out a new session, and a logout.
	w = s.post(t, peer, "/settings/password",
		url.Values{"current": {"pw12345678"}, "new": {"pw87654321"}, "confirm": {"pw87654321"}}, sc)
	require.Equal(t, http.StatusSeeOther, w.Code)
	sc = findCookie(w, "tunneld_session")
	require.NotNil(t, sc)
	require.Equal(t, http.StatusSeeOther, s.post(t, peer, "/logout", nil, sc).Code)

	// A password reset, requested and completed.
	s.mailer.Reset()
	require.Equal(t, http.StatusOK, s.post(t, peer, "/forgot-password", url.Values{"email": {email}}, nil).Code)
	require.Len(t, s.mailer.Sent(), 1)
	resetToken := extractResetToken(t, s.mailer.Sent()[0].TextBody)
	require.Equal(t, http.StatusSeeOther, s.post(t, peer, "/reset",
		url.Values{"token": {resetToken}, "new": {"pw-after-reset"}, "confirm": {"pw-after-reset"}}, nil).Code)

	rows := s.auditRows(t)
	byAction := map[string][]auditRow{}
	for _, r := range rows {
		byAction[r.Action] = append(byAction[r.Action], r)
	}
	want := []string{
		"auth.signup", "auth.email.verify", "auth.login.failure", "auth.login.success",
		"token.create", "token.revoke", "reservation.create", "reservation.release",
		"auth.password.change", "auth.logout", "auth.password.reset.request", "auth.password.reset.complete",
	}
	for _, action := range want {
		assert.Len(t, byAction[action], 1, action)
	}
	assert.Len(t, rows, len(want), "no other rows: %+v", rows)

	for _, r := range rows {
		require.NotNil(t, r.IP, r.Action)
		assert.Equal(t, "203.0.113.50", r.IP.String(), "%s records the peer address", r.Action)
		switch r.Action {
		case "auth.login.failure", "auth.password.reset.request":
			assert.Nil(t, r.UserID, "%s: nobody is logged in", r.Action)
		default:
			require.NotNil(t, r.UserID, r.Action)
			assert.Equal(t, uid, *r.UserID, r.Action)
		}
	}
	one := func(action string) map[string]any {
		require.Len(t, byAction[action], 1, action)
		return byAction[action][0].Metadata
	}
	assert.Equal(t, float64(tokenID), one("token.create")["token_id"])
	assert.Equal(t, "laptop", one("token.create")["name"])
	assert.Equal(t, float64(tokenID), one("token.revoke")["token_id"])
	assert.Equal(t, "audited", one("reservation.create")["subdomain"])
	assert.Equal(t, "audited", one("reservation.release")["subdomain"])
	assert.Equal(t, "invalid_credentials", one("auth.login.failure")["reason"])
	assert.Equal(t, float64(uid), one("auth.password.reset.request")["target_user_id"])
	for _, r := range rows {
		for _, v := range r.Metadata {
			assert.NotContains(t, fmt.Sprint(v), "pw", "%s: no password in the audit log", r.Action)
			assert.NotContains(t, fmt.Sprint(v), resetToken, "%s: no token in the audit log", r.Action)
		}
	}
}

func TestRefusedActionsWriteNoAuditRow(t *testing.T) {
	s := newStack(t, withAudit, func(o *Options, _ *stack) { o.LoginFailuresPerAccount = 1 })
	scA := doSignup(t, s.h, "a-audit@example.com", "pw12345678")
	scB := doSignup(t, s.h, "b-audit@example.com", "pw12345678")
	require.Equal(t, http.StatusOK, s.post(t, "", "/tokens", url.Values{"name": {"a-token"}}, scA).Code)
	tokenA := s.tokenIDByName(t, s.userID(t, "a-audit@example.com"), "a-token")
	before := len(s.auditRows(t))

	// A login over the limit: one failure is recorded, the refused attempt is not.
	require.Equal(t, http.StatusUnauthorized, s.login(t, "198.51.100.1:1", "a-audit@example.com", "wrong").Code)
	require.Equal(t, http.StatusTooManyRequests, s.login(t, "198.51.100.2:1", "a-audit@example.com", "wrong").Code)
	// Revoking somebody else's token, releasing a name nobody reserved, and
	// signing up with a taken address change nothing.
	require.Equal(t, http.StatusNotFound, postHTMX(t, s.h, scB, "/tokens", fmt.Sprintf("/tokens/%d/revoke", tokenA)).Code)
	require.Equal(t, http.StatusOK, postHTMX(t, s.h, scB, "/reservations", "/reservations/nothing-here/release").Code)
	require.Equal(t, http.StatusSeeOther, s.post(t, "198.51.100.3:1", "/signup",
		url.Values{"email": {"a-audit@example.com"}, "password": {"pw12345678"}}, nil).Code)
	// A field error.
	require.Equal(t, http.StatusUnprocessableEntity, s.post(t, "", "/reservations", url.Values{"subdomain": {"admin"}}, scA).Code)

	rows := s.auditRows(t)[before:]
	require.Len(t, rows, 1, "%+v", rows)
	assert.Equal(t, "auth.login.failure", rows[0].Action)
}

func TestDisabledAccountLoginIsAuditedAsFailure(t *testing.T) {
	s := newStack(t, withAudit)
	uid := s.createUser(t, "off@example.com", "pw12345678")
	require.NoError(t, s.users.Disable(context.Background(), nil, uid))
	require.Equal(t, http.StatusUnauthorized, s.login(t, "198.51.100.9:1", "off@example.com", "pw12345678").Code)
	rows := s.auditRows(t)
	require.Len(t, rows, 1)
	assert.Equal(t, "auth.login.failure", rows[0].Action)
	assert.Nil(t, rows[0].UserID)
	assert.Equal(t, "account_disabled", rows[0].Metadata["reason"])
}
