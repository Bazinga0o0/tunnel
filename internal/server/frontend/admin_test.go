package frontend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/audit"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/passwordreset"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// adminTestPassword is the password of the admin that newAdminTestEnv
// creates; the forms that need re-authentication send it.
const adminTestPassword = "admin-password-123"

// adminTestEnv is a frontend handler with every service the admin panel
// uses, an audit service, a registry, and one logged-in, verified admin.
type adminTestEnv struct {
	pool     *pgxpool.Pool
	h        http.Handler
	users    *users.Service
	tokens   *tokens.Service
	res      *reservations.Service
	sessions *sessions.Service
	reg      *registry.Registry
	audit    *audit.Service

	adminID     int64
	adminCookie *http.Cookie
	secure      bool // Options.CSRFSecure: selects the cookie names
}

// newAdminTestEnv builds the environment. configure, if given, can change
// the options before the handler is built.
func newAdminTestEnv(t *testing.T, configure ...func(*Options)) *adminTestEnv {
	t.Helper()
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	e := &adminTestEnv{
		pool:     pool,
		users:    users.NewService(pool),
		tokens:   tokens.NewService(pool),
		res:      reservations.NewService(pool),
		sessions: sessions.NewService(pool),
		reg:      registry.New(),
		audit:    audit.NewService(pool),
	}
	opts := Options{
		Domain:       "tunnel.localhost",
		Users:        e.users,
		Tokens:       e.tokens,
		Reservations: e.res,
		Sessions:     e.sessions,
		Registry:     e.reg,
		Audit:        e.audit,
		CSRFKey:      testCSRFKey,
		CSRFSecure:   false,
	}
	for _, c := range configure {
		c(&opts)
	}
	e.secure = opts.CSRFSecure
	e.h = New(opts)
	closeAtCleanup(t, e.h) // ends the audit budget's background check

	ctx := context.Background()
	admin, err := e.users.Create(ctx, "admin@example.com", adminTestPassword)
	require.NoError(t, err)
	require.NoError(t, e.users.MarkEmailVerified(ctx, admin.ID))
	require.NoError(t, e.users.Promote(ctx, admin.ID))
	e.adminID = admin.ID
	e.adminCookie = e.login(t, admin.ID)
	return e
}

// login creates a web session for userID and returns its cookie.
func (e *adminTestEnv) login(t *testing.T, userID int64) *http.Cookie {
	t.Helper()
	raw, _, err := e.sessions.Create(context.Background(), userID, "test", netip.Addr{}, time.Hour)
	require.NoError(t, err)
	return &http.Cookie{Name: sessionCookieName(e.secure), Value: raw}
}

// insertUser adds an account without the cost of a password hash.
func (e *adminTestEnv) insertUser(t *testing.T, email string, verified bool) int64 {
	t.Helper()
	id := dbtest.InsertUser(t, e.pool, email)
	if verified {
		require.NoError(t, e.users.MarkEmailVerified(context.Background(), id))
	}
	return id
}

// get sends a GET with the given session cookie (nil: none).
func (e *adminTestEnv) get(t *testing.T, cookie *http.Cookie, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

// post sends a form POST with a valid CSRF token and the given session
// cookie (nil: none). The token comes from the public login page, so the
// request passes the CSRF check whoever sends it.
func (e *adminTestEnv) post(t *testing.T, cookie *http.Cookie, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	token, csrfCookie := getCSRF(t, e.h, nil, "/login")
	if form == nil {
		form = url.Values{}
	}
	form.Set("gorilla.csrf.Token", token)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

// adminAuditRow is one row of audit_log as the admin tests read it.
type adminAuditRow struct {
	ActorID  *int64
	Metadata map[string]any
}

// auditRows returns the rows written for action, oldest first.
func (e *adminTestEnv) auditRows(t *testing.T, action string) []adminAuditRow {
	t.Helper()
	return auditRowsFor(t, e.pool, action)
}

func auditRowsFor(t *testing.T, pool *pgxpool.Pool, action string) []adminAuditRow {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT user_id, metadata FROM audit_log WHERE action = $1 ORDER BY id`, action)
	require.NoError(t, err)
	defer rows.Close()
	var out []adminAuditRow
	for rows.Next() {
		var r adminAuditRow
		var raw []byte
		require.NoError(t, rows.Scan(&r.ActorID, &raw))
		if len(raw) > 0 {
			require.NoError(t, json.Unmarshal(raw, &r.Metadata))
		}
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

// requireOneAdminAudit checks that exactly one row was written for action,
// with the env's admin as actor, and returns its metadata.
func (e *adminTestEnv) requireOneAdminAudit(t *testing.T, action string) map[string]any {
	t.Helper()
	rows := e.auditRows(t, action)
	require.Len(t, rows, 1, "audit rows for %s", action)
	require.NotNil(t, rows[0].ActorID, "the acting admin is the actor of %s", action)
	assert.Equal(t, e.adminID, *rows[0].ActorID)
	return rows[0].Metadata
}

// callAdminHandler runs one admin handler directly, without the router and
// its middleware, as user actorID and with the given chi URL parameters.
// Tests use it for states the full router cannot reach, such as an actor
// who stopped being an active admin after the admin check.
func callAdminHandler(t *testing.T, h http.HandlerFunc, actorID int64, path string, params map[string]string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, ctxUserID, actorID)
	w := httptest.NewRecorder()
	h(w, req.WithContext(ctx))
	return w
}

// ---- the admin URL space answers like a path that does not exist ----

func TestAdminAnswersStandardNotFoundToEverybodyButAdmins(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()

	// The router's own answer for a path that does not exist.
	standard := e.get(t, nil, "/no-such-page-anywhere")
	require.Equal(t, http.StatusNotFound, standard.Code)

	userID := e.insertUser(t, "plain-user@example.com", true)
	userCookie := e.login(t, userID)

	// An admin who was demoted keeps a valid session (Demote leaves the
	// sessions alone): the admin check, not the session, must refuse.
	demoted := e.insertUser(t, "demoted-admin@example.com", true)
	require.NoError(t, e.users.Promote(ctx, demoted))
	demotedCookie := e.login(t, demoted)
	require.NoError(t, e.users.Demote(ctx, demoted))

	// An admin whose account was disabled behind the service's back, so that
	// the session row is still there (users.Disable would delete it).
	disabledAdmin := e.insertUser(t, "disabled-admin@example.com", true)
	require.NoError(t, e.users.Promote(ctx, disabledAdmin))
	disabledCookie := e.login(t, disabledAdmin)
	_, err := e.pool.Exec(ctx, `UPDATE users SET disabled_at = now() WHERE id = $1`, disabledAdmin)
	require.NoError(t, err)
	require.Equal(t, 1, e.countRows(t, "sessions", disabledAdmin), "the session row stays")

	callers := map[string]*http.Cookie{
		"no session":                        nil,
		"unknown session":                   {Name: sessionCookieName(false), Value: "not-a-session"},
		"user who is no admin":              userCookie,
		"demoted admin with a live session": demotedCookie,
		"disabled admin, session row kept":  disabledCookie,
	}
	getPaths := []string{"/admin", "/admin/", "/admin/users", "/admin/users/1", "/admin/connections/status", "/admin/no-such-admin-page"}
	postPaths := []string{"/admin/users/1/disable", "/admin/reservations/grant", "/admin/connections/x/kill"}

	for name, cookie := range callers {
		for _, p := range getPaths {
			w := e.get(t, cookie, p)
			assert.Equal(t, http.StatusNotFound, w.Code, "%s: GET %s", name, p)
			assert.Equal(t, standard.Body.String(), w.Body.String(), "%s: GET %s must look like a missing page", name, p)
			assert.Empty(t, w.Header().Get("Location"), "%s: GET %s must not redirect", name, p)
		}
		for _, p := range postPaths {
			w := e.post(t, cookie, p, nil)
			assert.Equal(t, http.StatusNotFound, w.Code, "%s: POST %s", name, p)
			assert.Equal(t, standard.Body.String(), w.Body.String(), "%s: POST %s must look like a missing page", name, p)
		}
	}

	// The admin still gets in, and the target user was not touched.
	w := e.get(t, e.adminCookie, "/admin")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Admin overview")
	u, err := e.users.FindByID(ctx, 1)
	require.NoError(t, err)
	assert.False(t, u.DisabledAt.Valid, "a refused POST changes nothing")
}

func TestAdminNotFoundFollowsTheRoutersNotFoundHandler(t *testing.T) {
	// adminNotFound answers with the handler the router uses for unknown
	// paths, whatever that handler is.
	r := chi.NewRouter()
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("custom not found"))
	})
	r.Get("/x", func(w http.ResponseWriter, r *http.Request) { adminNotFound(w, r) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "custom not found", w.Body.String())

	// Outside a chi router it falls back to the standard library's answer.
	w = httptest.NewRecorder()
	adminNotFound(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "404 page not found\n", w.Body.String())
}

// ---- user actions: unknown IDs, audit ----

// countRows counts the rows of table that belong to userID.
func (e *adminTestEnv) countRows(t *testing.T, table string, userID int64) int {
	t.Helper()
	var n int
	require.NoError(t, e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM `+table+` WHERE user_id = $1`, userID).Scan(&n))
	return n
}

func (e *adminTestEnv) passwordHash(t *testing.T, userID int64) string {
	t.Helper()
	var h string
	require.NoError(t, e.pool.QueryRow(context.Background(),
		`SELECT password_hash FROM users WHERE id = $1`, userID).Scan(&h))
	return h
}

// directOptions are the options of e for a handler called directly.
// The rate limiters are those of e's handler, as New would share them.
func (e *adminTestEnv) directOptions() Options {
	return Options{Users: e.users, Sessions: e.sessions, Tokens: e.tokens,
		Reservations: e.res, Registry: e.reg, Audit: e.audit,
		limiters: e.h.(*frontendHandler).limiters}
}

func TestAdminDisableClosesTheUsersTunnelSessions(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	target := e.insertUser(t, "disable-me@example.com", true)
	other := e.insertUser(t, "bystander@example.com", true)

	withTunnel := &fakeCloseableSession{id: "target-http", userID: target}
	require.NoError(t, e.reg.RegisterHTTP("targetapp", withTunnel))
	withoutTunnel := &fakeCloseableSession{id: "target-idle", userID: target}
	require.NoError(t, e.reg.AddSession(withoutTunnel, registry.SessionLimits{}))
	bystander := &fakeCloseableSession{id: "other-http", userID: other}
	require.NoError(t, e.reg.RegisterHTTP("otherapp", bystander))

	w := e.post(t, e.adminCookie, "/admin/users/"+itoa(target)+"/disable", nil)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())

	u, err := e.users.FindByID(ctx, target)
	require.NoError(t, err)
	assert.True(t, u.DisabledAt.Valid)
	assert.True(t, withTunnel.closed, "the tunnel session of the disabled user is closed")
	assert.True(t, withoutTunnel.closed, "a session without a tunnel is closed too")
	_, still := e.reg.LookupHTTP("targetapp")
	assert.False(t, still)
	assert.False(t, bystander.closed, "sessions of other users stay open")

	md := e.requireOneAdminAudit(t, "admin.user.disable")
	assert.Equal(t, float64(target), md["target_user_id"])
	assert.Equal(t, "disable-me@example.com", md["target_email"])
	assert.Equal(t, float64(2), md["sessions_closed"])
}

func TestAdminDisableSurfacesLastAdmin(t *testing.T) {
	// The router cannot reach this state: the acting admin is an active admin
	// and so never leaves the target as the last one. It happens when the
	// actor loses the admin role while the request runs; the handler is
	// called directly with an actor who is no admin any more.
	e := newAdminTestEnv(t)
	actor := e.insertUser(t, "former-admin@example.com", true)
	sess := &fakeCloseableSession{id: "last-admin-session", userID: e.adminID}
	require.NoError(t, e.reg.AddSession(sess, registry.SessionLimits{}))

	w := callAdminHandler(t, adminUserDisable(e.directOptions()),
		actor, "/admin/users/x/disable", map[string]string{"id": itoa(e.adminID)}, url.Values{})

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "last active admin")
	u, err := e.users.FindByID(context.Background(), e.adminID)
	require.NoError(t, err)
	assert.False(t, u.DisabledAt.Valid, "the last admin stays enabled")
	assert.False(t, sess.closed, "a refused disable closes no session")
	assert.Empty(t, e.auditRows(t, "admin.user.disable"))
}

func TestAdminRevokeTokensActionRevokesEveryTokenAndClosesSessions(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	target := e.insertUser(t, "tokens@example.com", true)
	other := e.insertUser(t, "keeps-token@example.com", true)

	raw1, _, err := e.tokens.Issue(ctx, target, "laptop")
	require.NoError(t, err)
	raw2, _, err := e.tokens.Issue(ctx, target, "ci")
	require.NoError(t, err)
	_, gone, err := e.tokens.Issue(ctx, target, "old")
	require.NoError(t, err)
	_, err = e.tokens.RevokeAny(ctx, gone.ID)
	require.NoError(t, err)
	otherRaw, _, err := e.tokens.Issue(ctx, other, "theirs")
	require.NoError(t, err)

	sess := &fakeCloseableSession{id: "token-session", userID: target}
	require.NoError(t, e.reg.RegisterTCP(15000, sess))
	otherSess := &fakeCloseableSession{id: "other-token-session", userID: other}
	require.NoError(t, e.reg.RegisterTCP(15001, otherSess))

	// The detail page offers the action.
	page := e.get(t, e.adminCookie, "/admin/users/"+itoa(target))
	require.Equal(t, http.StatusOK, page.Code)
	assert.Contains(t, page.Body.String(), `action="/admin/users/`+itoa(target)+`/revoke-tokens"`)

	w := e.post(t, e.adminCookie, "/admin/users/"+itoa(target)+"/revoke-tokens", nil)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())

	active, err := e.tokens.ListActiveByUser(ctx, target)
	require.NoError(t, err)
	assert.Empty(t, active, "no active token is left")
	for _, raw := range []string{raw1, raw2} {
		_, err := e.tokens.Verify(ctx, raw)
		assert.ErrorIs(t, err, tokens.ErrInvalidToken)
	}
	assert.True(t, sess.closed, "the user's tunnel session is closed")
	_, err = e.tokens.Verify(ctx, otherRaw)
	assert.NoError(t, err, "tokens of other users stay valid")
	assert.False(t, otherSess.closed)

	md := e.requireOneAdminAudit(t, "admin.user.tokens_revoke")
	assert.Equal(t, float64(target), md["target_user_id"])
	assert.Equal(t, float64(2), md["tokens_revoked"])
	assert.Equal(t, float64(1), md["sessions_closed"])
}

func TestAdminRevokeTokensActionThatStopsHalfWay(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	target := e.insertUser(t, "half-revoked@example.com", true)
	_, older, err := e.tokens.Issue(ctx, target, "older")
	require.NoError(t, err)
	_, newer, err := e.tokens.Issue(ctx, target, "newer")
	require.NoError(t, err)
	// The list is ordered by created_at; make the order certain.
	_, err = e.pool.Exec(ctx, `UPDATE api_tokens SET created_at = now() - interval '1 hour' WHERE id = $1`, older.ID)
	require.NoError(t, err)
	sess := &fakeCloseableSession{id: "half-revoked-session", userID: target}
	require.NoError(t, e.reg.AddSession(sess, registry.SessionLimits{}))

	// Tokens are revoked newest first; make the revoke of the older one
	// fail. The trigger name starts with dbtest_fail_delete_ so that
	// dbtest.Pool removes it should this test be killed before its cleanup.
	_, err = e.pool.Exec(ctx, fmt.Sprintf(`CREATE OR REPLACE FUNCTION admin_revoke_test_fail() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN
			IF OLD.id = %d THEN RAISE EXCEPTION 'injected-revoke-failure'; END IF;
			RETURN NEW;
		END $$`, older.ID))
	require.NoError(t, err)
	_, err = e.pool.Exec(ctx, `CREATE TRIGGER dbtest_fail_delete_admin_revoke BEFORE UPDATE ON api_tokens
		FOR EACH ROW EXECUTE FUNCTION admin_revoke_test_fail()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = e.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS dbtest_fail_delete_admin_revoke ON api_tokens`)
		_, _ = e.pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS admin_revoke_test_fail()`)
	})

	w := e.post(t, e.adminCookie, "/admin/users/"+itoa(target)+"/revoke-tokens", nil)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "injected-revoke-failure")

	active, err := e.tokens.ListActiveByUser(ctx, target)
	require.NoError(t, err)
	require.Len(t, active, 1, "the newer token was revoked before the failure")
	assert.Equal(t, older.ID, active[0].ID)
	assert.NotEqual(t, newer.ID, active[0].ID)
	assert.True(t, sess.closed, "the sessions are closed even so")

	md := e.requireOneAdminAudit(t, "admin.user.tokens_revoke")
	assert.Equal(t, float64(1), md["tokens_revoked"])
	assert.Equal(t, true, md["incomplete"])
	assert.Equal(t, float64(1), md["sessions_closed"])
}

func TestAdminEnablingOwnAccountIsRefused(t *testing.T) {
	e := newAdminTestEnv(t)
	w := e.post(t, e.adminCookie, "/admin/users/"+itoa(e.adminID)+"/enable", nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, e.auditRows(t, "admin.user.enable"))
}

func TestAdminVerifyAndEnableAreAudited(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	target := e.insertUser(t, "audit-target@example.com", false)

	w := e.post(t, e.adminCookie, "/admin/users/"+itoa(target)+"/verify", nil)
	require.Equal(t, http.StatusSeeOther, w.Code)
	md := e.requireOneAdminAudit(t, "admin.user.verify")
	assert.Equal(t, float64(target), md["target_user_id"])

	require.NoError(t, e.users.Disable(ctx, nil, target))
	w = e.post(t, e.adminCookie, "/admin/users/"+itoa(target)+"/enable", nil)
	require.Equal(t, http.StatusSeeOther, w.Code)
	u, err := e.users.FindByID(ctx, target)
	require.NoError(t, err)
	assert.False(t, u.DisabledAt.Valid)
	md = e.requireOneAdminAudit(t, "admin.user.enable")
	assert.Equal(t, float64(target), md["target_user_id"])
}

func TestAdminActionsOnAUserThatDoesNotExistAnswerNotFound(t *testing.T) {
	e := newAdminTestEnv(t)
	standard := e.get(t, nil, "/no-such-page-anywhere").Body.String()
	form := url.Values{"current_password": {adminTestPassword}, "new_password": {"a-new-password-123"}}
	for _, id := range []string{"999999", "0", "-3", "abc"} {
		for _, action := range []string{"verify", "disable", "enable", "promote", "demote", "reset-password", "revoke-tokens"} {
			w := e.post(t, e.adminCookie, "/admin/users/"+id+"/"+action, form)
			assert.Equal(t, http.StatusNotFound, w.Code, "%s on user %s", action, id)
			assert.Equal(t, standard, w.Body.String(), "%s on user %s", action, id)
		}
	}
	var n int
	require.NoError(t, e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action LIKE 'admin.%'`).Scan(&n))
	assert.Zero(t, n, "nothing happened, nothing is audited")
}

func TestAdminPromoteRequiresTheCurrentPassword(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	target := e.insertUser(t, "promote-me@example.com", true)
	path := "/admin/users/" + itoa(target) + "/promote"

	for name, tc := range map[string]struct {
		form url.Values
		want string
	}{
		// A missing password is refused before any hash is computed.
		"missing": {url.Values{}, "Enter your current password"},
		"wrong":   {url.Values{"current_password": {"not-my-password"}}, "Your current password is not correct"},
	} {
		w := e.post(t, e.adminCookie, path, tc.form)
		assert.Equal(t, http.StatusForbidden, w.Code, name)
		assert.Contains(t, w.Body.String(), tc.want, name)
		assert.Contains(t, w.Body.String(), "promote-me@example.com", "%s: the detail page is shown again", name)
		u, err := e.users.FindByID(ctx, target)
		require.NoError(t, err)
		assert.False(t, u.IsAdmin, "%s password: nothing changes", name)
	}
	assert.Empty(t, e.auditRows(t, "admin.user.promote"))

	w := e.post(t, e.adminCookie, path, url.Values{"current_password": {adminTestPassword}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	u, err := e.users.FindByID(ctx, target)
	require.NoError(t, err)
	assert.True(t, u.IsAdmin)
	md := e.requireOneAdminAudit(t, "admin.user.promote")
	assert.Equal(t, float64(target), md["target_user_id"])
	assert.Equal(t, "promote-me@example.com", md["target_email"])
}

func TestAdminPromoteRefusesAnUnverifiedTarget(t *testing.T) {
	e := newAdminTestEnv(t)
	target := e.insertUser(t, "unverified@example.com", false)

	w := e.post(t, e.adminCookie, "/admin/users/"+itoa(target)+"/promote",
		url.Values{"current_password": {adminTestPassword}})
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "not verified")
	u, err := e.users.FindByID(context.Background(), target)
	require.NoError(t, err)
	assert.False(t, u.IsAdmin)
	assert.Empty(t, e.auditRows(t, "admin.user.promote"))
}

func TestAdminDemoteRequiresTheCurrentPassword(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	target := e.insertUser(t, "demote-me@example.com", true)
	require.NoError(t, e.users.Promote(ctx, target))
	path := "/admin/users/" + itoa(target) + "/demote"

	w := e.post(t, e.adminCookie, path, url.Values{"current_password": {"not-my-password"}})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "current password")
	u, err := e.users.FindByID(ctx, target)
	require.NoError(t, err)
	assert.True(t, u.IsAdmin, "a wrong password changes nothing")
	assert.Empty(t, e.auditRows(t, "admin.user.demote"))

	w = e.post(t, e.adminCookie, path, url.Values{"current_password": {adminTestPassword}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	u, err = e.users.FindByID(ctx, target)
	require.NoError(t, err)
	assert.False(t, u.IsAdmin)
	md := e.requireOneAdminAudit(t, "admin.user.demote")
	assert.Equal(t, float64(target), md["target_user_id"])
}

func TestAdminDemoteSurfacesLastAdmin(t *testing.T) {
	// As in TestAdminDisableSurfacesLastAdmin: the actor lost the admin role
	// while the request ran, so the target is the last active admin.
	e := newAdminTestEnv(t)
	ctx := context.Background()
	actor, err := e.users.Create(ctx, "former-admin@example.com", "former-admin-pw-1")
	require.NoError(t, err)

	w := callAdminHandler(t, adminUserDemote(e.directOptions()),
		actor.ID, "/admin/users/x/demote", map[string]string{"id": itoa(e.adminID)},
		url.Values{"current_password": {"former-admin-pw-1"}})

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "last active admin")
	u, err := e.users.FindByID(ctx, e.adminID)
	require.NoError(t, err)
	assert.True(t, u.IsAdmin)
	assert.Empty(t, e.auditRows(t, "admin.user.demote"))
}

func TestAdminPasswordResetRequiresTheCurrentPasswordAndUsesTheServicePath(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	target, err := e.users.Create(ctx, "reset-me@example.com", "the-old-password-1")
	require.NoError(t, err)
	path := "/admin/users/" + itoa(target.ID) + "/reset-password"
	before := e.passwordHash(t, target.ID)

	w := e.post(t, e.adminCookie, path, url.Values{
		"new_password": {"a-brand-new-password"}, "current_password": {"not-my-password"},
	})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "current password")
	assert.Equal(t, before, e.passwordHash(t, target.ID), "a wrong password changes nothing")
	assert.Empty(t, e.auditRows(t, "admin.user.password_reset"))

	// Eleven characters, 22 bytes: too short by the rune count.
	w = e.post(t, e.adminCookie, path, url.Values{
		"new_password": {"ääääääääääá"}, "current_password": {adminTestPassword},
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "at least 12 characters")
	assert.Equal(t, before, e.passwordHash(t, target.ID))

	// An open reset link and a web session of the target go with the reset.
	_, _, _, err = passwordreset.NewService(e.pool, e.users, e.sessions).IssueWithAddress(ctx, "reset-me@example.com")
	require.NoError(t, err)
	e.login(t, target.ID)
	require.Equal(t, 1, e.countRows(t, "password_resets", target.ID))
	require.Equal(t, 1, e.countRows(t, "sessions", target.ID))

	w = e.post(t, e.adminCookie, path, url.Values{
		"new_password": {"a-brand-new-password"}, "current_password": {adminTestPassword},
	})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	ok, err := e.users.VerifyPassword(ctx, target.ID, "a-brand-new-password")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Zero(t, e.countRows(t, "password_resets", target.ID), "open reset links are deleted")
	assert.Zero(t, e.countRows(t, "sessions", target.ID), "the target is logged out")

	md := e.requireOneAdminAudit(t, "admin.user.password_reset")
	assert.Equal(t, float64(target.ID), md["target_user_id"])
	for k, v := range md {
		assert.NotContains(t, fmt.Sprint(v), "a-brand-new-password", "metadata %s must not carry the password", k)
		assert.NotContains(t, fmt.Sprint(v), adminTestPassword, "metadata %s must not carry the password", k)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// ---- reservations: grants and revokes, audit ----

// grant posts the grant form.
func (e *adminTestEnv) grant(t *testing.T, resType, key, email string) *httptest.ResponseRecorder {
	t.Helper()
	return e.post(t, e.adminCookie, "/admin/reservations/grant", url.Values{
		"type": {resType}, "key": {key}, "email": {email},
	})
}

// reservationCount counts the rows of a reservation table.
func (e *adminTestEnv) reservationCount(t *testing.T, table string) int {
	t.Helper()
	var n int
	require.NoError(t, e.pool.QueryRow(context.Background(), `SELECT count(*) FROM `+table).Scan(&n))
	return n
}

func TestAdminGrantNormalisesTheSubdomainAndRefusesBadNames(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	owner := e.insertUser(t, "owner@example.com", true)
	e.insertUser(t, "second@example.com", true)

	w := e.grant(t, "subdomain", "  MyApp ", "owner@example.com")
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	got, reserved, err := e.res.Owner(ctx, "myapp")
	require.NoError(t, err)
	assert.True(t, reserved, "the name is stored in its normal form")
	assert.Equal(t, owner, got)

	for _, tc := range []struct{ key, want string }{
		{"../../users/7/promote?x=", "Invalid subdomain"},
		{"a.b.c", "Invalid subdomain"},
		{"ab", "Invalid subdomain"},
		{"admin", "reserved for system use"},
		{"WWW", "reserved for system use"},
	} {
		w := e.grant(t, "subdomain", tc.key, "owner@example.com")
		assert.Equal(t, http.StatusBadRequest, w.Code, tc.key)
		assert.Contains(t, w.Body.String(), tc.want, tc.key)
	}
	assert.Equal(t, 1, e.reservationCount(t, "reserved_subdomains"), "no refused name was stored")

	// A name that is taken: a fixed message, no database text.
	w = e.grant(t, "subdomain", "MYAPP", "second@example.com")
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "already reserved")
	for _, raw := range []string{"duplicate", "SQLSTATE", "23505", "violates"} {
		assert.NotContains(t, w.Body.String(), raw)
	}

	// An unknown address.
	w = e.grant(t, "subdomain", "free-name", "nobody@example.com")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "user not found")
}

func TestAdminGrantOfAnUnknownTypeAnswers400(t *testing.T) {
	e := newAdminTestEnv(t)
	e.insertUser(t, "owner@example.com", true)
	for _, typ := range []string{"bogus", "", "SUBDOMAIN", "http"} {
		w := e.grant(t, typ, "some-name", "owner@example.com")
		assert.Equal(t, http.StatusBadRequest, w.Code, "type %q", typ)
	}
	assert.Zero(t, e.reservationCount(t, "reserved_subdomains"), "an unknown type is no subdomain grant")
	assert.Empty(t, e.auditRows(t, "admin.reservation.grant"))
}

func TestAdminGrantParsesPortsStrictly(t *testing.T) {
	e := newAdminTestEnv(t)
	e.insertUser(t, "owner@example.com", true)
	for _, typ := range []string{"tcp", "udp"} {
		for _, key := range []string{"65536", "4294967376", "0x50", "-1", "80.5", "0", "", "1e3", "８０"} {
			w := e.grant(t, typ, key, "owner@example.com")
			assert.Equal(t, http.StatusBadRequest, w.Code, "%s port %q", typ, key)
			assert.Contains(t, w.Body.String(), "Invalid port", "%s port %q", typ, key)
		}
	}
	assert.Zero(t, e.reservationCount(t, "reserved_tcp_ports"))
	assert.Zero(t, e.reservationCount(t, "reserved_udp_ports"))
	assert.Empty(t, e.auditRows(t, "admin.reservation.grant"))
}

func TestAdminGrantKeepsPortsInsideTheConfiguredRange(t *testing.T) {
	e := newAdminTestEnv(t, func(o *Options) {
		o.TCPPortRange = PortRange{Low: 10000, High: 20000}
		o.UDPPortRange = PortRange{Low: 30000, High: 40000}
	})
	ctx := context.Background()
	e.insertUser(t, "owner@example.com", true)

	for _, tc := range []struct {
		typ  string
		port string
		ok   bool
	}{
		{"tcp", "9999", false}, {"tcp", "10000", true}, {"tcp", "20000", true}, {"tcp", "20001", false},
		{"tcp", "35000", false},
		{"udp", "29999", false}, {"udp", "30000", true}, {"udp", "40000", true}, {"udp", "40001", false},
		{"udp", "15000", false},
	} {
		w := e.grant(t, tc.typ, tc.port, "owner@example.com")
		if tc.ok {
			assert.Equal(t, http.StatusSeeOther, w.Code, "%s %s: %s", tc.typ, tc.port, w.Body.String())
		} else {
			assert.Equal(t, http.StatusBadRequest, w.Code, "%s %s", tc.typ, tc.port)
			assert.Contains(t, w.Body.String(), "outside the configured", "%s %s", tc.typ, tc.port)
		}
	}
	_, reserved, err := e.res.OwnerTCPPort(ctx, 9999)
	require.NoError(t, err)
	assert.False(t, reserved)
	assert.Equal(t, 2, e.reservationCount(t, "reserved_tcp_ports"))
	assert.Equal(t, 2, e.reservationCount(t, "reserved_udp_ports"))
}

func TestAdminGrantClosesSessionsOfOtherUsersOnTheNameOrPort(t *testing.T) {
	e := newAdminTestEnv(t)
	owner := e.insertUser(t, "owner@example.com", true)
	other := e.insertUser(t, "squatter@example.com", true)

	foreignHTTP := &fakeCloseableSession{id: "foreign-http", userID: other}
	require.NoError(t, e.reg.RegisterHTTP("contested", foreignHTTP))
	ownHTTP := &fakeCloseableSession{id: "own-http", userID: owner}
	require.NoError(t, e.reg.RegisterHTTP("mine-already", ownHTTP))
	foreignTCP := &fakeCloseableSession{id: "foreign-tcp", userID: other}
	require.NoError(t, e.reg.RegisterTCP(15000, foreignTCP))
	foreignUDP := &fakeCloseableSession{id: "foreign-udp", userID: other}
	require.NoError(t, e.reg.RegisterUDP(35000, foreignUDP))
	unrelated := &fakeCloseableSession{id: "unrelated", userID: other}
	require.NoError(t, e.reg.RegisterTCP(15001, unrelated))

	require.Equal(t, http.StatusSeeOther, e.grant(t, "subdomain", "Contested", "owner@example.com").Code)
	assert.True(t, foreignHTTP.closed, "another user's tunnel on the granted name is closed")
	_, still := e.reg.LookupHTTP("contested")
	assert.False(t, still)

	require.Equal(t, http.StatusSeeOther, e.grant(t, "subdomain", "mine-already", "owner@example.com").Code)
	assert.False(t, ownHTTP.closed, "the new owner's own tunnel stays open")

	require.Equal(t, http.StatusSeeOther, e.grant(t, "tcp", "15000", "owner@example.com").Code)
	assert.True(t, foreignTCP.closed, "another user's tunnel on the granted TCP port is closed")
	require.Equal(t, http.StatusSeeOther, e.grant(t, "udp", "35000", "owner@example.com").Code)
	assert.True(t, foreignUDP.closed, "another user's tunnel on the granted UDP port is closed")
	assert.False(t, unrelated.closed, "a tunnel on another port stays open")

	rows := e.auditRows(t, "admin.reservation.grant")
	require.Len(t, rows, 4)
	assert.Equal(t, map[string]any{
		"type": "subdomain", "subdomain": "contested", "target_user_id": float64(owner),
		"target_email": "owner@example.com", "sessions_closed": float64(1),
	}, rows[0].Metadata)
	assert.Equal(t, float64(0), rows[1].Metadata["sessions_closed"])
	assert.Equal(t, "tcp", rows[2].Metadata["type"])
	assert.Equal(t, float64(15000), rows[2].Metadata["port"])
	assert.Equal(t, "udp", rows[3].Metadata["type"])
	assert.Equal(t, float64(35000), rows[3].Metadata["port"])
	for _, r := range rows {
		require.NotNil(t, r.ActorID)
		assert.Equal(t, e.adminID, *r.ActorID)
	}
}

func TestAdminGrantNeverShowsDatabaseErrorText(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	e.insertUser(t, "owner@example.com", true)

	// Make every insert into reserved_subdomains fail with a recognisable
	// text. The trigger name starts with dbtest_fail_delete_ so that
	// dbtest.Pool removes it should this test be killed before its cleanup.
	_, err := e.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION admin_grant_test_fail() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected-database-failure-7f3a'; END $$`)
	require.NoError(t, err)
	_, err = e.pool.Exec(ctx, `CREATE TRIGGER dbtest_fail_delete_admin_grant BEFORE INSERT ON reserved_subdomains
		FOR EACH ROW EXECUTE FUNCTION admin_grant_test_fail()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = e.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS dbtest_fail_delete_admin_grant ON reserved_subdomains`)
		_, _ = e.pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS admin_grant_test_fail()`)
	})

	w := e.grant(t, "subdomain", "will-fail", "owner@example.com")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "could not be stored")
	assert.NotContains(t, w.Body.String(), "injected-database-failure-7f3a")
	assert.NotContains(t, w.Body.String(), "SQLSTATE")
	assert.Empty(t, e.auditRows(t, "admin.reservation.grant"))
}

func TestAdminRevokeTakesTheKeyFromTheFormBody(t *testing.T) {
	e := newAdminTestEnv(t)
	ctx := context.Background()
	owner := e.insertUser(t, "owner@example.com", true)

	// Names written before names were checked: none of them passes
	// NormalizeSubdomain, all of them must stay revocable.
	legacy := []string{"bad/name", "../../users/7/promote?x=", "MixedCase", "with space"}
	for _, name := range legacy {
		_, err := e.pool.Exec(ctx, `INSERT INTO reserved_subdomains (subdomain, user_id) VALUES ($1, $2)`, name, owner)
		require.NoError(t, err)
	}
	require.NoError(t, e.res.GrantTCPPort(ctx, 7777, owner))

	page := e.get(t, e.adminCookie, "/admin/reservations")
	require.Equal(t, http.StatusOK, page.Code)
	body := page.Body.String()
	assert.Contains(t, body, `action="/admin/reservations/subdomain/revoke"`)
	assert.Contains(t, body, `hx-post="/admin/reservations/subdomain/revoke"`)
	assert.Contains(t, body, `name="key" value="../../users/7/promote?x="`, "the name travels in the body")
	assert.NotContains(t, body, `/admin/reservations/subdomain/../`, "no stored name ends up in a URL")
	assert.NotContains(t, body, `#res-sd-`, "no stored name ends up in a selector")

	for _, name := range legacy {
		w := e.post(t, e.adminCookie, "/admin/reservations/subdomain/revoke", url.Values{"key": {name}})
		require.Equal(t, http.StatusOK, w.Code, name)
		_, reserved, err := e.res.Owner(ctx, name)
		require.NoError(t, err)
		assert.False(t, reserved, "%q is revoked", name)
	}

	w := e.post(t, e.adminCookie, "/admin/reservations/tcp/revoke", url.Values{"key": {"7777"}})
	require.Equal(t, http.StatusOK, w.Code)
	_, reserved, err := e.res.OwnerTCPPort(ctx, 7777)
	require.NoError(t, err)
	assert.False(t, reserved)

	rows := e.auditRows(t, "admin.reservation.revoke")
	require.Len(t, rows, len(legacy)+1)
	assert.Equal(t, map[string]any{"type": "subdomain", "subdomain": "bad/name", "target_user_id": float64(owner)}, rows[0].Metadata)
	assert.Equal(t, map[string]any{"type": "tcp", "port": float64(7777), "target_user_id": float64(owner)}, rows[len(legacy)].Metadata)
	require.NotNil(t, rows[0].ActorID)
	assert.Equal(t, e.adminID, *rows[0].ActorID)

	// Nothing to revoke: no change, no entry.
	w = e.post(t, e.adminCookie, "/admin/reservations/subdomain/revoke", url.Values{"key": {"never-reserved"}})
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Len(t, e.auditRows(t, "admin.reservation.revoke"), len(legacy)+1)
}

// ---- connections, users list, overview, kill audit ----

func TestAdminConnectionsShowsAtMost200RowsAndSaysSo(t *testing.T) {
	e := newAdminTestEnv(t)
	for i := 0; i < 205; i++ {
		s := &fakeCloseableSession{id: fmt.Sprintf("s-%03d", i), connectedAt: time.Now().Add(-time.Duration(i) * time.Second)}
		require.NoError(t, e.reg.AddSession(s, registry.SessionLimits{PerUser: -1, Total: -1}))
	}
	w := e.get(t, e.adminCookie, "/admin/connections/status")
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Equal(t, 200, strings.Count(body, `<tr id="conn-`))
	assert.Contains(t, body, "Showing the newest 200 of 205 connections.")
	// Newest first: the five oldest are the ones left out.
	assert.Contains(t, body, `id="conn-s-000"`)
	assert.Contains(t, body, `id="conn-s-199"`)
	assert.NotContains(t, body, `id="conn-s-200"`)

	// At the limit there is no note.
	e.reg.KillSession("s-200")
	for i := 201; i < 205; i++ {
		e.reg.KillSession(fmt.Sprintf("s-%03d", i))
	}
	w = e.get(t, e.adminCookie, "/admin/connections/status")
	assert.Equal(t, 200, strings.Count(w.Body.String(), `<tr id="conn-`))
	assert.NotContains(t, w.Body.String(), "Showing the newest")
}

func TestAdminConnectionsTruncatesDisplayedValues(t *testing.T) {
	e := newAdminTestEnv(t)
	long := strings.Repeat("a", 90) + "@example.com"
	owner := e.insertUser(t, long, true)
	s := &fakeCloseableSession{id: "long-owner", userID: owner, connectedAt: time.Now()}
	require.NoError(t, e.reg.RegisterHTTP("longowner", s))

	w := e.get(t, e.adminCookie, "/admin/connections/status")
	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), long)
	assert.Contains(t, w.Body.String(), strings.Repeat("a", 63)+"…")
	assert.NotContains(t, w.Body.String(), strings.Repeat("a", 64))
}

func TestAdminConnectionsListsAndKillsSessionsWithoutATunnel(t *testing.T) {
	e := newAdminTestEnv(t)
	owner := e.insertUser(t, "idle@example.com", true)
	idle := &fakeCloseableSession{id: "idle-session", userID: owner, connectedAt: time.Now()}
	require.NoError(t, e.reg.AddSession(idle, registry.SessionLimits{}))

	w := e.get(t, e.adminCookie, "/admin/connections/status")
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, ">session</span>")
	assert.Contains(t, body, "idle@example.com")
	assert.Contains(t, body, `action="/admin/connections/idle-session/kill"`)

	w = e.post(t, e.adminCookie, "/admin/connections/idle-session/kill", nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, idle.closed)
	md := e.requireOneAdminAudit(t, "admin.connection.kill")
	assert.Equal(t, "idle-session", md["session_id"])
	assert.Equal(t, float64(owner), md["target_user_id"])

	// A session that is gone: 404, no second entry.
	w = e.post(t, e.adminCookie, "/admin/connections/idle-session/kill", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Len(t, e.auditRows(t, "admin.connection.kill"), 1)
}

func TestAdminConnectionKillURLIsPathEscaped(t *testing.T) {
	e := newAdminTestEnv(t)
	odd := &fakeCloseableSession{id: "a/b c?d", userID: 0, connectedAt: time.Now()}
	require.NoError(t, e.reg.RegisterTCP(15005, odd))

	w := e.get(t, e.adminCookie, "/admin/connections/status")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `action="/admin/connections/a%2Fb%20c%3Fd/kill"`)
	assert.Contains(t, w.Body.String(), `hx-post="/admin/connections/a%2Fb%20c%3Fd/kill"`)

	w = e.post(t, e.adminCookie, "/admin/connections/a%2Fb%20c%3Fd/kill", nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, odd.closed)
	md := e.requireOneAdminAudit(t, "admin.connection.kill")
	assert.Equal(t, "a/b c?d", md["session_id"])
	assert.NotContains(t, md, "target_user_id", "a session without a user names none")
}

func TestAdminUsersPageBoundsThePageNumber(t *testing.T) {
	e := newAdminTestEnv(t)
	// 21 accounts with the admin: two pages, so the page number is shown.
	for i := 0; i < 20; i++ {
		e.insertUser(t, fmt.Sprintf("paged-%02d@example.com", i), false)
	}
	// math.MaxInt32 / 20 = 107374182 is the highest page served; its offset
	// (107374181 * 20) still fits an int32.
	for page, shown := range map[string]int{
		"200000000":               107374182,
		"107374183":               107374182,
		"107374182":               107374182,
		"99999999999":             107374182,
		"99999999999999999999999": 1, // not an int at all
		"-5":                      1,
		"x":                       1,
		"2":                       2,
	} {
		w := e.get(t, e.adminCookie, "/admin/users?page="+page)
		require.Equal(t, http.StatusOK, w.Code, "page=%s", page)
		assert.Contains(t, w.Body.String(), fmt.Sprintf("Page %d of 2", shown), "page=%s", page)
	}

	// A page past the end is empty and leads back to the last page.
	w := e.get(t, e.adminCookie, "/admin/users?page=200000000")
	assert.Contains(t, w.Body.String(), "No users on this page.")
	assert.Contains(t, w.Body.String(), `href="/admin/users?q=&amp;page=2"`)
}

func TestAdminUsersPaginationEscapesTheSearchTerm(t *testing.T) {
	e := newAdminTestEnv(t)
	for i := 0; i < 21; i++ {
		e.insertUser(t, fmt.Sprintf("q&x-%02d@example.com", i), false)
	}
	w := e.get(t, e.adminCookie, "/admin/users?q="+url.QueryEscape("q&x"))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `href="/admin/users?q=q%26x&amp;page=2"`)

	w = e.get(t, e.adminCookie, "/admin/users?q="+url.QueryEscape("q&x")+"&page=2")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `href="/admin/users?q=q%26x&amp;page=1"`)
	assert.Equal(t, 1, strings.Count(w.Body.String(), "q&amp;x-"), "page 2 holds the 21st match")
}

func TestAdminOverviewWorksWithoutARegistry(t *testing.T) {
	e := newAdminTestEnv(t, func(o *Options) { o.Registry = nil })
	w := e.get(t, e.adminCookie, "/admin")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Admin overview")
	w = e.get(t, e.adminCookie, "/admin/connections/status")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminRevokeRefusesUnknownTypesAndBadPorts(t *testing.T) {
	e := newAdminTestEnv(t)
	for _, tc := range []struct{ typ, key string }{
		{"bogus", "x"}, {"subdomain", ""}, {"tcp", "abc"}, {"tcp", "70000"}, {"udp", "0"}, {"udp", "-1"},
	} {
		w := e.post(t, e.adminCookie, "/admin/reservations/"+tc.typ+"/revoke", url.Values{"key": {tc.key}})
		assert.Equal(t, http.StatusBadRequest, w.Code, "%s %q", tc.typ, tc.key)
	}
}
