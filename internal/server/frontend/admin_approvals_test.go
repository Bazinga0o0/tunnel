package frontend

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// withApprovalMode sets up the admin test environment in approval mode with
// a mailer, so that an approval sends its mail.
func withApprovalMode(tm *mail.TestMailer) func(*Options) {
	return func(o *Options) {
		o.SignupMode = "approval"
		o.Mailer = tm
		o.PublicBaseURL = "https://app.tunnel.localhost"
	}
}

func TestBulkApproveAndReject(t *testing.T) {
	tm := mail.NewTestMailer()
	e := newAdminTestEnv(t, withApprovalMode(tm))
	ctx := context.Background()
	one := e.insertUser(t, "wait-1@example.com", true)
	two := e.insertUser(t, "wait-2@example.com", false)
	three := e.insertUser(t, "wait-3@example.com", true)

	w := e.get(t, e.adminCookie, "/admin/approvals")
	require.Equal(t, http.StatusOK, w.Code)
	for _, email := range []string{"wait-1@example.com", "wait-2@example.com", "wait-3@example.com"} {
		assert.Contains(t, w.Body.String(), email)
	}
	assert.Contains(t, w.Body.String(), "Freischaltungen (3)", "the menu counts the waiting accounts")

	w = e.post(t, e.adminCookie, "/admin/approvals", url.Values{"action": {"approve"}, "id": {itoa(one), itoa(two)}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = e.post(t, e.adminCookie, "/admin/approvals", url.Values{"action": {"reject"}, "id": {itoa(three)}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "Freischaltungen (0)")

	for _, id := range []int64{one, two} {
		u, err := e.users.FindByID(ctx, id)
		require.NoError(t, err)
		assert.True(t, users.IsApproved(u), "account %d is approved", id)
	}
	_, err := e.users.FindByID(ctx, three)
	assert.ErrorIs(t, err, users.ErrNotFound, "the rejected account is deleted")

	approved := e.auditRows(t, "admin.user.approve")
	require.Len(t, approved, 2)
	rejected := e.auditRows(t, "admin.user.reject")
	require.Len(t, rejected, 1)
	targets := map[float64]bool{}
	for _, row := range append(approved, rejected...) {
		require.NotNil(t, row.ActorID)
		assert.Equal(t, e.adminID, *row.ActorID)
		targets[row.Metadata["target_user_id"].(float64)] = true
	}
	assert.Equal(t, map[float64]bool{float64(one): true, float64(two): true, float64(three): true}, targets)

	drainMail(t, e.h)
	var to []string
	for _, m := range tm.Sent() {
		to = append(to, m.To)
		assert.Contains(t, m.TextBody, "https://app.tunnel.localhost/login")
	}
	assert.ElementsMatch(t, []string{"wait-1@example.com", "wait-2@example.com"}, to,
		"the approved accounts get the mail, the rejected one does not")
}

func TestRejectSkipsAdminsAndSelf(t *testing.T) {
	e := newAdminTestEnv(t, withApprovalMode(mail.NewTestMailer()))
	ctx := context.Background()
	// An admin that was never approved: DeletePending would refuse it as
	// well, the handler must not even try.
	other := e.insertUser(t, "other-admin@example.com", true)
	require.NoError(t, e.users.Promote(ctx, other))

	w := e.post(t, e.adminCookie, "/admin/approvals", url.Values{"action": {"reject"}, "id": {itoa(other), itoa(e.adminID)}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := w.Body.String()
	assert.Contains(t, body, "other-admin@example.com: übersprungen, Admin")
	assert.Contains(t, body, "admin@example.com: übersprungen, eigenes Konto")

	for _, id := range []int64{other, e.adminID} {
		_, err := e.users.FindByID(ctx, id)
		assert.NoError(t, err, "account %d stays", id)
	}
	assert.Empty(t, e.auditRows(t, "admin.user.reject"))
}

// A disabled account that waits gets no approve button on its detail page,
// and an approval (button or approvals page) sends its owner no mail: the
// owner cannot log in. An account that waits and is not disabled keeps
// both.
func TestApprovalOfADisabledAccountSendsNoMail(t *testing.T) {
	tm := mail.NewTestMailer()
	e := newAdminTestEnv(t, withApprovalMode(tm))
	ctx := context.Background()
	waiting := e.insertUser(t, "waiting@example.com", true)
	viaButton := e.insertUser(t, "disabled-button@example.com", true)
	viaPage := e.insertUser(t, "disabled-page@example.com", true)
	_, err := e.pool.Exec(ctx, `UPDATE users SET disabled_at = now() WHERE id = ANY($1)`, []int64{viaButton, viaPage})
	require.NoError(t, err)

	approveForm := func(id int64) string { return `action="/admin/users/` + itoa(id) + `/approve"` }
	w := e.get(t, e.adminCookie, "/admin/users/"+itoa(waiting))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), approveForm(waiting), "an account that waits has the button")
	w = e.get(t, e.adminCookie, "/admin/users/"+itoa(viaButton))
	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), approveForm(viaButton), "a disabled account has none")

	w = e.post(t, e.adminCookie, "/admin/users/"+itoa(viaButton)+"/approve", nil)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	w = e.post(t, e.adminCookie, "/admin/approvals", url.Values{"action": {"approve"}, "id": {itoa(viaPage), itoa(waiting)}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	for _, id := range []int64{waiting, viaButton, viaPage} {
		u, err := e.users.FindByID(ctx, id)
		require.NoError(t, err)
		assert.True(t, users.IsApproved(u), "account %d is approved", id)
	}
	drainMail(t, e.h)
	var to []string
	for _, m := range tm.Sent() {
		to = append(to, m.To)
	}
	assert.Equal(t, []string{"waiting@example.com"}, to, "only the account that is not disabled gets the mail")
}
