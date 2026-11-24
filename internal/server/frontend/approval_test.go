package frontend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
	"github.com/Bazinga0o0/tunnel/internal/server/verifications"
)

// awaitingApprovalBanner is the start of the dashboard's banner for an
// account that waits for approval.
const awaitingApprovalBanner = "Dein Konto wartet auf Freischaltung durch einen Admin."

// In approval mode a new account with a verified address can sign in, but
// creating a token or a reservation is refused until an admin approves it;
// the dashboard says why. Closed mode gates the same way.
func TestPendingAccountCannotCreateTokenOrReservation(t *testing.T) {
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	userSvc := users.NewService(pool)
	tokSvc := tokens.NewService(pool)
	resSvc := reservations.NewService(pool)
	sessSvc := sessions.NewService(pool)
	tm := mail.NewTestMailer()
	h := New(Options{
		Domain:        "tunnel.localhost",
		Users:         userSvc,
		Tokens:        tokSvc,
		Reservations:  resSvc,
		Sessions:      sessSvc,
		Registry:      registry.New(),
		CSRFKey:       testCSRFKey,
		Mailer:        tm,
		Verifications: verifications.NewService(pool, userSvc),
		PublicBaseURL: "https://app.tunnel.localhost",
		SignupMode:    "approval",
	})
	closeAtCleanup(t, h)

	sc := doSignup(t, h, "pending@example.com", "pw12345678")
	require.Equal(t, http.StatusSeeOther, confirmVerification(t, h, extractVerifyToken(t, tm.Sent()[0])).Code)
	u, err := userSvc.FindByEmail(ctx, "pending@example.com")
	require.NoError(t, err)
	dashboard := func() string {
		req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		req.AddCookie(sc)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		return w.Body.String()
	}

	for path, form := range map[string]url.Values{
		"/tokens":       {"name": {"Laptop"}},
		"/reservations": {"subdomain": {"myapp"}},
	} {
		w := postForm(t, h, sc, path, form)
		require.Equal(t, http.StatusSeeOther, w.Code, path)
		assert.Equal(t, "/dashboard?awaiting_approval=1", w.Header().Get("Location"), path)
	}
	n, err := tokSvc.CountActiveByUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Zero(t, n, "no token stored")
	held, err := resSvc.ListByUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Empty(t, held, "no reservation stored")
	assert.Contains(t, dashboard(), awaitingApprovalBanner)

	require.NoError(t, userSvc.Approve(ctx, u.ID))
	w := postForm(t, h, sc, "/tokens", url.Values{"name": {"Laptop"}})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "twbl_")
	n, err = tokSvc.CountActiveByUser(ctx, u.ID)
	require.NoError(t, err)
	assert.EqualValues(t, 1, n, "token stored after approval")
	assert.NotContains(t, dashboard(), awaitingApprovalBanner)

	// Closed mode: nobody can sign up there, so the waiting account is
	// inserted and signed in directly.
	hClosed := New(Options{
		Domain:       "tunnel.localhost",
		Users:        userSvc,
		Tokens:       tokSvc,
		Reservations: resSvc,
		Sessions:     sessSvc,
		Registry:     registry.New(),
		CSRFKey:      testCSRFKey,
		SignupMode:   "closed",
	})
	closeAtCleanup(t, hClosed)
	waiting := dbtest.InsertUser(t, pool, "waiting@example.com")
	require.NoError(t, userSvc.MarkEmailVerified(ctx, waiting))
	raw, _, err := sessSvc.Create(ctx, waiting, "test", netip.Addr{}, time.Hour)
	require.NoError(t, err)
	w = postForm(t, hClosed, &http.Cookie{Name: sessionCookieName(false), Value: raw}, "/tokens", url.Values{"name": {"Laptop"}})
	require.Equal(t, http.StatusSeeOther, w.Code, "closed mode")
	assert.Equal(t, "/dashboard?awaiting_approval=1", w.Header().Get("Location"), "closed mode")
	n, err = tokSvc.CountActiveByUser(ctx, waiting)
	require.NoError(t, err)
	assert.Zero(t, n, "no token stored in closed mode")
}

// An admin who grants a waiting account a port approves the account with
// it: otherwise the account could not use what it was given. The approval
// has an audit row of its own, also when the grant is refused.
func TestAdminGrantApprovesTarget(t *testing.T) {
	e := newAdminTestEnv(t, func(o *Options) { o.SignupMode = "approval" })
	ctx := context.Background()
	target := e.insertUser(t, "pending@example.com", true)
	grant := func(port, email string) *httptest.ResponseRecorder {
		return e.post(t, e.adminCookie, "/admin/reservations/grant", url.Values{
			"type": {"tcp"}, "key": {port}, "email": {email},
		})
	}
	// approvedIDs returns the target_user_id of every admin.user.approve row.
	approvedIDs := func() []any {
		var ids []any
		for _, row := range e.auditRows(t, "admin.user.approve") {
			require.NotNil(t, row.ActorID)
			assert.Equal(t, e.adminID, *row.ActorID, "the admin is the actor")
			assert.Equal(t, "admin.reservation.grant", row.Metadata["via"])
			ids = append(ids, row.Metadata["target_user_id"])
		}
		return ids
	}

	w := grant("20001", "pending@example.com")
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	u, err := e.users.FindByID(ctx, target)
	require.NoError(t, err)
	assert.True(t, users.IsApproved(u), "the grant approves the account")
	owner, held, err := e.res.OwnerTCPPort(ctx, 20001)
	require.NoError(t, err)
	assert.True(t, held)
	assert.Equal(t, target, owner)
	assert.Equal(t, []any{float64(target)}, approvedIDs(), "one approve row")

	// A refused grant (the port is held) keeps the approval and its row.
	other := e.insertUser(t, "other@example.com", true)
	w = grant("20001", "other@example.com")
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	u, err = e.users.FindByID(ctx, other)
	require.NoError(t, err)
	assert.True(t, users.IsApproved(u), "approved before the refused grant")
	assert.Equal(t, []any{float64(target), float64(other)}, approvedIDs(), "approve row despite the refusal")

	// An account that is approved already gets no further approve row.
	w = grant("20002", "pending@example.com")
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Len(t, approvedIDs(), 2, "no row for an account that was approved")
}
