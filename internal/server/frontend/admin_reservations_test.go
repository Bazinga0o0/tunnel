package frontend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// newAdminReservationsHandler builds a handler backed by a real DB pool and
// returns the handler plus the services so tests can seed data.
func newAdminReservationsHandler(t *testing.T) (http.Handler, *users.Service, *reservations.Service) {
	t.Helper()
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	userSvc := users.NewService(pool)
	resSvc := reservations.NewService(pool)
	h := New(Options{
		Domain:       "tunnel.localhost",
		Users:        userSvc,
		Tokens:       tokens.NewService(pool),
		Reservations: resSvc,
		Sessions:     sessions.NewService(pool),
		CSRFKey:      testCSRFKey,
		CSRFSecure:   false,
	})
	return h, userSvc, resSvc
}

// setupAdminRes signs up a user, promotes to admin, returns handler + session cookie.
func setupAdminRes(t *testing.T, email string) (http.Handler, *users.Service, *reservations.Service, *http.Cookie) {
	t.Helper()
	h, userSvc, resSvc := newAdminReservationsHandler(t)
	sc := doSignup(t, h, email, "pw12345678")
	u, err := userSvc.FindByEmail(context.Background(), email)
	require.NoError(t, err)
	require.NoError(t, userSvc.Promote(context.Background(), u.ID))
	return h, userSvc, resSvc, sc
}

// ---- Page rendering tests ----

func TestAdminReservationsDefaultTabIsSubdomain(t *testing.T) {
	h, _, _, sc := setupAdminRes(t, "res-default@b.example.com")

	req := httptest.NewRequest("GET", "/admin/reservations", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "Reservations")
	assert.Contains(t, body, "Subdomains")
	assert.Contains(t, body, "?tab=tcp")
	assert.Contains(t, body, "?tab=udp")
}

func TestAdminReservationsTCPTabRendered(t *testing.T) {
	h, _, _, sc := setupAdminRes(t, "res-tcp-tab@b.example.com")

	req := httptest.NewRequest("GET", "/admin/reservations?tab=tcp", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "No tcp port reservations")
}

func TestAdminReservationsUDPTabRendered(t *testing.T) {
	h, _, _, sc := setupAdminRes(t, "res-udp-tab@b.example.com")

	req := httptest.NewRequest("GET", "/admin/reservations?tab=udp", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "No udp port reservations")
}

func TestAdminReservationsSubdomainTabShowsEntries(t *testing.T) {
	h, userSvc, resSvc, sc := setupAdminRes(t, "res-sd-show@b.example.com")
	ctx := context.Background()

	other, err := userSvc.Create(ctx, "other-sd@b.example.com", "pw12345678")
	require.NoError(t, err)
	require.NoError(t, resSvc.Reserve(ctx, "myapp", other.ID))

	req := httptest.NewRequest("GET", "/admin/reservations", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "myapp")
	assert.Contains(t, body, "other-sd@b.example.com")
}

func TestAdminReservationsNonAdminForbidden(t *testing.T) {
	h, _, _ := newAdminReservationsHandler(t)
	sc := doSignup(t, h, "res-nonadmin@b.example.com", "pw12345678")

	req := httptest.NewRequest("GET", "/admin/reservations", nil)
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

// ---- Grant action tests ----

func TestAdminReservationsGrantSubdomainHappy(t *testing.T) {
	h, userSvc, resSvc, sc := setupAdminRes(t, "grant-sd-h@b.example.com")
	ctx := context.Background()

	target, err := userSvc.Create(ctx, "target-sd@b.example.com", "pw12345678")
	require.NoError(t, err)
	_ = target

	w := postForm(t, h, sc, "/admin/reservations/grant", url.Values{
		"type":  {"subdomain"},
		"key":   {"granted"},
		"email": {"target-sd@b.example.com"},
	})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/reservations?tab=subdomain", w.Header().Get("Location"))

	owner, reserved, err := resSvc.Owner(ctx, "granted")
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, target.ID, owner)
}

func TestAdminReservationsGrantTCPHappy(t *testing.T) {
	h, userSvc, resSvc, sc := setupAdminRes(t, "grant-tcp-h@b.example.com")
	ctx := context.Background()

	target, err := userSvc.Create(ctx, "target-tcp@b.example.com", "pw12345678")
	require.NoError(t, err)

	w := postForm(t, h, sc, "/admin/reservations/grant", url.Values{
		"type":  {"tcp"},
		"key":   {"8080"},
		"email": {"target-tcp@b.example.com"},
	})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/reservations?tab=tcp", w.Header().Get("Location"))

	owner, reserved, err := resSvc.OwnerTCPPort(ctx, 8080)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, target.ID, owner)
}

func TestAdminReservationsGrantUDPHappy(t *testing.T) {
	h, userSvc, resSvc, sc := setupAdminRes(t, "grant-udp-h@b.example.com")
	ctx := context.Background()

	target, err := userSvc.Create(ctx, "target-udp@b.example.com", "pw12345678")
	require.NoError(t, err)

	w := postForm(t, h, sc, "/admin/reservations/grant", url.Values{
		"type":  {"udp"},
		"key":   {"9090"},
		"email": {"target-udp@b.example.com"},
	})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/reservations?tab=udp", w.Header().Get("Location"))

	owner, reserved, err := resSvc.OwnerUDPPort(ctx, 9090)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, target.ID, owner)
}

func TestAdminReservationsGrantInvalidEmail(t *testing.T) {
	h, _, _, sc := setupAdminRes(t, "grant-inv-email@b.example.com")

	w := postForm(t, h, sc, "/admin/reservations/grant", url.Values{
		"type":  {"subdomain"},
		"key":   {"whatever"},
		"email": {"nobody@notexist.example.com"},
	})
	// Should render the page with an error banner, not redirect.
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "user not found")
}

func TestAdminReservationsGrantInvalidPortReturnsError(t *testing.T) {
	h, userSvc, _, sc := setupAdminRes(t, "grant-inv-port@b.example.com")
	ctx := context.Background()
	_, err := userSvc.Create(ctx, "valid-user@b.example.com", "pw12345678")
	require.NoError(t, err)

	w := postForm(t, h, sc, "/admin/reservations/grant", url.Values{
		"type":  {"tcp"},
		"key":   {"notaport"},
		"email": {"valid-user@b.example.com"},
	})
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid port")
}

// ---- Revoke action tests ----

func TestAdminReservationsRevokeSubdomainHappy(t *testing.T) {
	h, userSvc, resSvc, sc := setupAdminRes(t, "revoke-sd-h@b.example.com")
	ctx := context.Background()

	other, err := userSvc.Create(ctx, "own-sd@b.example.com", "pw12345678")
	require.NoError(t, err)
	require.NoError(t, resSvc.Reserve(ctx, "torevoke", other.ID))

	w := postForm(t, h, sc, "/admin/reservations/subdomain/revoke", url.Values{"key": {"torevoke"}})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.String())

	_, reserved, _ := resSvc.Owner(ctx, "torevoke")
	assert.False(t, reserved)
}

func TestAdminReservationsRevokeTCPHappy(t *testing.T) {
	h, userSvc, resSvc, sc := setupAdminRes(t, "revoke-tcp-h@b.example.com")
	ctx := context.Background()

	other, err := userSvc.Create(ctx, "own-tcp@b.example.com", "pw12345678")
	require.NoError(t, err)
	require.NoError(t, resSvc.ReserveTCPPort(ctx, 7777, other.ID))

	w := postForm(t, h, sc, "/admin/reservations/tcp/revoke", url.Values{"key": {"7777"}})
	require.Equal(t, http.StatusOK, w.Code)

	_, reserved, _ := resSvc.OwnerTCPPort(ctx, 7777)
	assert.False(t, reserved)
}

func TestAdminReservationsRevokeNonexistentIsNoOp(t *testing.T) {
	h, _, _, sc := setupAdminRes(t, "revoke-noexist@b.example.com")

	w := postForm(t, h, sc, "/admin/reservations/subdomain/revoke", url.Values{"key": {"never"}})
	require.Equal(t, http.StatusOK, w.Code)
}
