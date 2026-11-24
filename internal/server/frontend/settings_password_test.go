package frontend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
)

// changePassword posts the settings form of the user with session cookie sc
// from the peer address peer. When the answer sets a new session cookie, sc
// is replaced by it.
func (s *stack) changePassword(t *testing.T, peer string, sc **http.Cookie, current, newPW string) *httptest.ResponseRecorder {
	t.Helper()
	w := s.post(t, peer, "/settings/password", url.Values{"current": {current}, "new": {newPW}, "confirm": {newPW}}, *sc)
	if c := findCookie(w, "tunneld_session"); c != nil && c.Value != "" {
		*sc = c
	}
	return w
}

// passwordWorks reports whether email and password still log in, checked
// through the service (no rate limiter involved).
func (s *stack) passwordWorks(t *testing.T, email, password string) bool {
	t.Helper()
	_, err := s.users.Authenticate(context.Background(), email, password)
	return err == nil
}

func TestSettingsPasswordChangeCountsFailuresPerAccount(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) { o.LoginFailuresPerAccount = 3 })
	sc := doSignup(t, s.h, "settings@example.com", "pw12345678")
	lim := limitersOf(t, s.h)
	key := accountKey("settings@example.com")

	// Each failure comes from another address: only the account counts here.
	for i, peer := range []string{"198.51.100.150:1", "198.51.100.151:1"} {
		w := s.changePassword(t, peer, &sc, "wrong-current", "new-password-1")
		require.Equal(t, http.StatusUnauthorized, w.Code, "failure %d", i+1)
		assert.Contains(t, w.Body.String(), "current password is incorrect")
	}
	require.Equal(t, 2, lim.loginAccount.count(key), "each wrong current password counts")

	// A correct current password gives its slots back.
	w := s.changePassword(t, "198.51.100.152:1", &sc, "pw12345678", "new-password-1")
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, 2, lim.loginAccount.count(key))
	assert.Zero(t, lim.loginIP.count(sourceKey(clientIP(&http.Request{RemoteAddr: "198.51.100.152:1"}))))

	w = s.changePassword(t, "198.51.100.153:1", &sc, "wrong-again", "new-password-2")
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Equal(t, 3, lim.loginAccount.count(key))

	// Over the limit: the 429 of the login, before any password check, even
	// with the right current password, and nothing changes.
	w = s.changePassword(t, "198.51.100.154:1", &sc, "new-password-1", "new-password-3")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), msgTooManyLogins)
	assert.Positive(t, retryAfterSeconds(t, w))
	assert.True(t, s.passwordWorks(t, "settings@example.com", "new-password-1"), "the refused change changed nothing")
	assert.False(t, s.passwordWorks(t, "settings@example.com", "new-password-3"))
	assert.Equal(t, 3, lim.loginAccount.count(key), "a refused attempt is not counted again")

	// The budget is the login's: the login of the account is refused too.
	w = s.login(t, "198.51.100.155:1", "settings@example.com", "new-password-1")
	require.Equal(t, http.StatusTooManyRequests, w.Code)

	// After the window the change goes through again.
	s.clock.Advance(15*time.Minute + time.Second)
	w = s.changePassword(t, "198.51.100.156:1", &sc, "new-password-1", "new-password-3")
	require.Equal(t, http.StatusSeeOther, w.Code)
}

func TestSettingsPasswordChangeCountsFailuresPerAddress(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) { o.LoginFailuresPerIP = 2 })
	sc := doSignup(t, s.h, "per-ip@example.com", "pw12345678")
	const peer = "198.51.100.160:1"

	// One failed login and one failed password change from the same address
	// fill its budget of 2.
	require.Equal(t, http.StatusUnauthorized, s.login(t, peer, "someone-else@example.com", "wrong").Code)
	require.Equal(t, http.StatusUnauthorized, s.changePassword(t, peer, &sc, "wrong-current", "new-password-1").Code)

	w := s.changePassword(t, peer, &sc, "pw12345678", "new-password-1")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), msgTooManyLogins)
	assert.Positive(t, retryAfterSeconds(t, w))
	assert.True(t, s.passwordWorks(t, "per-ip@example.com", "pw12345678"))

	// Another address is not affected.
	require.Equal(t, http.StatusSeeOther, s.changePassword(t, "198.51.100.161:1", &sc, "pw12345678", "new-password-1").Code)
}

// The password update and the end of the sessions are one transaction: when
// the sessions cannot be deleted, the password stays the old one, every
// session stays alive and the browser keeps its cookie.
func TestSettingsPasswordChangeIsOneTransaction(t *testing.T) {
	s := newStack(t)
	scOther := doSignup(t, s.h, "tx-change@example.com", "pw12345678")
	sc := findCookie(s.login(t, "198.51.100.190:1", "tx-change@example.com", "pw12345678"), "tunneld_session")
	require.NotNil(t, sc)
	before := *sc

	undo := dbtestFailDeletes(t, s, "sessions")
	w := s.changePassword(t, "198.51.100.190:1", &sc, "pw12345678", "new-password-1")
	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), msgInternal)
	assert.NotContains(t, w.Body.String(), "injected failure")
	assert.Nil(t, findCookie(w, "tunneld_session"), "the cookie is neither replaced nor cleared")
	undo()

	assert.True(t, s.passwordWorks(t, "tx-change@example.com", "pw12345678"), "the password was not changed")
	assert.False(t, s.passwordWorks(t, "tx-change@example.com", "new-password-1"))
	for name, c := range map[string]*http.Cookie{"current": sc, "other": scOther} {
		assert.Equal(t, http.StatusOK, serve(s.h, withCookie(t, "/settings", c)).Code, "%s session stays", name)
	}

	// Repeated without the failure, the change goes through: every earlier
	// session has ended, the browser works with the new cookie it got.
	w = s.changePassword(t, "198.51.100.190:1", &sc, "pw12345678", "new-password-1")
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.NotEqual(t, before.Value, sc.Value, "a new session cookie")
	assert.Equal(t, http.StatusOK, serve(s.h, withCookie(t, "/settings", sc)).Code)
	assert.Equal(t, http.StatusSeeOther, serve(s.h, withCookie(t, "/settings", &before)).Code)
	assert.Equal(t, http.StatusSeeOther, serve(s.h, withCookie(t, "/settings", scOther)).Code)
}

// sessionsOf counts the stored sessions of the account userID.
func (s *stack) sessionsOf(t *testing.T, userID int64) int {
	t.Helper()
	var n int
	require.NoError(t, s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1`, userID).Scan(&n))
	return n
}

// auditCount counts the audit rows of action.
func (s *stack) auditCount(t *testing.T, action string) int {
	t.Helper()
	var n int
	require.NoError(t, s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n))
	return n
}

// A password change on the settings page ends every session of the account
// in the transaction that stores the password, the session it came from
// included, and gives that browser a new session the way a login does: a
// copy of the old cookie no longer logs anybody in.
func TestSettingsPasswordChangeRotatesTheSession(t *testing.T) {
	s := newStack(t, withAudit)
	const email, peer = "rotate@example.com", "198.51.100.200:1"
	scOther := doSignup(t, s.h, email, "pw12345678")
	uid := s.userID(t, email)
	login := s.login(t, peer, email, "pw12345678")
	sc := findCookie(login, "tunneld_session")
	require.NotNil(t, sc)
	copied := *sc // somebody else's copy of the cookie, taken before the change
	bystander := doSignup(t, s.h, "rotate-bystander@example.com", "pw12345678")
	require.Equal(t, 2, s.sessionsOf(t, uid))
	logins := s.auditCount(t, "auth.login.success")

	w := s.post(t, peer, "/settings/password",
		url.Values{"current": {"pw12345678"}, "new": {"new-password-1"}, "confirm": {"new-password-1"}}, sc)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/settings?changed=1", w.Header().Get("Location"))
	fresh := findCookie(w, "tunneld_session")
	require.NotNil(t, fresh, "the browser gets a new session cookie")
	require.NotEmpty(t, fresh.Value)
	assert.NotEqual(t, copied.Value, fresh.Value)
	// The attributes of the login's cookie.
	assert.Equal(t, sc.Path, fresh.Path)
	assert.Equal(t, sc.HttpOnly, fresh.HttpOnly)
	assert.True(t, fresh.HttpOnly)
	assert.Equal(t, sc.Secure, fresh.Secure)
	assert.Equal(t, sc.SameSite, fresh.SameSite)
	assert.WithinDuration(t, time.Now().Add(sessionTTL), fresh.Expires, time.Minute)

	// The old session id is refused behind the login; the new cookie works.
	w = serve(s.h, withCookie(t, "/dashboard", &copied))
	require.Equal(t, http.StatusSeeOther, w.Code, "the copied cookie no longer logs in")
	assert.Equal(t, "/login", w.Header().Get("Location"))
	assert.Equal(t, http.StatusOK, serve(s.h, withCookie(t, "/dashboard", fresh)).Code)
	// Every other session of the account has ended; the new one is the only
	// one left. Another account's session is untouched.
	assert.Equal(t, http.StatusSeeOther, serve(s.h, withCookie(t, "/dashboard", scOther)).Code)
	assert.Equal(t, 1, s.sessionsOf(t, uid))
	assert.Equal(t, http.StatusOK, serve(s.h, withCookie(t, "/dashboard", bystander)).Code)

	assert.True(t, s.passwordWorks(t, email, "new-password-1"))
	assert.False(t, s.passwordWorks(t, email, "pw12345678"))
	// The audit log gets the change; the new session is not a login.
	assert.Equal(t, 1, s.auditCount(t, "auth.password.change"))
	assert.Equal(t, logins, s.auditCount(t, "auth.login.success"))
}

// When the new session cannot be stored, the password is changed and no
// session of the account is left: the answer clears the cookie and sends
// the browser to the login page, which says that the password was changed.
// It never falls back to the old session.
func TestSettingsPasswordChangeWithoutANewSession(t *testing.T) {
	s := newStack(t, withAudit)
	const email, peer = "no-new-session@example.com", "198.51.100.201:1"
	scOther := doSignup(t, s.h, email, "pw12345678")
	uid := s.userID(t, email)
	sc := findCookie(s.login(t, peer, email, "pw12345678"), "tunneld_session")
	require.NotNil(t, sc)
	bystander := doSignup(t, s.h, "no-new-session-bystander@example.com", "pw12345678")

	failInserts(t, s, "sessions")
	w := s.post(t, peer, "/settings/password",
		url.Values{"current": {"pw12345678"}, "new": {"new-password-1"}, "confirm": {"new-password-1"}}, sc)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/login?changed=1", w.Header().Get("Location"))
	cleared := findCookie(w, "tunneld_session")
	require.NotNil(t, cleared, "the answer clears the session cookie")
	assert.Empty(t, cleared.Value)
	assert.Negative(t, cleared.MaxAge)

	assert.True(t, s.passwordWorks(t, email, "new-password-1"), "the password is changed")
	assert.False(t, s.passwordWorks(t, email, "pw12345678"))
	assert.Zero(t, s.sessionsOf(t, uid), "no session of the account is left")
	for name, c := range map[string]*http.Cookie{"current": sc, "other": scOther} {
		w := serve(s.h, withCookie(t, "/dashboard", c))
		assert.Equal(t, http.StatusSeeOther, w.Code, "%s session has ended", name)
		assert.Equal(t, "/login", w.Header().Get("Location"), name)
	}
	assert.Equal(t, http.StatusOK, serve(s.h, withCookie(t, "/dashboard", bystander)).Code)
	assert.Equal(t, 1, s.auditCount(t, "auth.password.change"), "the password did change")

	w = serve(s.h, httptest.NewRequest(http.MethodGet, "/login?changed=1", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Your password was changed. Please log in with your new password.")
	w = serve(s.h, httptest.NewRequest(http.MethodGet, "/login", nil))
	assert.NotContains(t, w.Body.String(), "Your password was changed", "only after a change")
}

// The password change on the settings page shares the per-user budget of
// the user area's actions (Options.UserActionsPerHour): every request that
// reaches it counts. Over the budget it is refused on the settings page
// with 429 and Retry-After, before any hash, and nothing changes. Another
// user is not affected.
func TestSettingsPasswordChangeCountsAgainstUserActions(t *testing.T) {
	s := newStack(t, withAudit, func(o *Options, _ *stack) { o.UserActionsPerHour = 2 })
	const email, peer = "budget@example.com", "198.51.100.250:1"
	sc := doSignup(t, s.h, email, "pw12345678")
	uid := s.userID(t, email)
	other := doSignup(t, s.h, "budget-other@example.com", "pw12345678")

	// A token and a password change with a wrong current password use up
	// the budget of 2: every request counts, whatever its outcome.
	require.Equal(t, http.StatusOK, s.post(t, peer, "/tokens", url.Values{"name": {"t1"}}, sc).Code)
	require.Equal(t, http.StatusUnauthorized, s.changePassword(t, peer, &sc, "wrong-current", "new-password-1").Code)
	require.Equal(t, 2, limitersOf(t, s.h).userActions.count(userActionKey(uid)))

	hashes := countHashes(t, "pw12345678")
	before := *sc
	w := s.changePassword(t, peer, &sc, "pw12345678", "new-password-1")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Positive(t, retryAfterSeconds(t, w))
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	body := w.Body.String()
	assert.Contains(t, body, msgTooManyUserActions, "the settings page says why")
	assert.Contains(t, body, `action="/settings/password"`, "the settings page itself, not a bare text")
	assert.Contains(t, body, email)
	assert.Nil(t, findCookie(w, "tunneld_session"), "the session is left alone")
	assert.Zero(t, hashes.Load(), "refused before any hash")

	assert.True(t, s.passwordWorks(t, email, "pw12345678"), "the password is unchanged")
	assert.False(t, s.passwordWorks(t, email, "new-password-1"))
	assert.Equal(t, http.StatusOK, serve(s.h, withCookie(t, "/settings", &before)).Code, "the session stays")
	assert.Zero(t, s.auditCount(t, "auth.password.change"))

	// The budget is the one of the token and reservation actions.
	assert.Equal(t, http.StatusTooManyRequests, s.post(t, peer, "/tokens", url.Values{"name": {"t2"}}, sc).Code)

	// Another user is not affected.
	assert.Equal(t, http.StatusSeeOther, s.changePassword(t, "198.51.100.251:1", &other, "pw12345678", "new-password-1").Code)

	// After the window the change goes through.
	s.clock.Advance(time.Hour + time.Second)
	assert.Equal(t, http.StatusSeeOther, s.changePassword(t, peer, &sc, "pw12345678", "new-password-1").Code)
}

// After a password change a request that still carries the old cookie must
// not delete the new one: an htmx request (the tunnels page polls its
// status every 3 s) is sent to the login page as before, but without the
// header that clears the session cookie, which the browser would apply to
// the new cookie of the same name. A plain navigation with the old cookie
// still clears it.
func TestALateHTMXRequestWithTheOldCookieKeepsTheNewOne(t *testing.T) {
	s := newStack(t)
	const email, peer = "late-request@example.com", "198.51.100.252:1"
	sc := doSignup(t, s.h, email, "pw12345678")
	old := *sc
	require.Equal(t, http.StatusSeeOther, s.changePassword(t, peer, &sc, "pw12345678", "new-password-1").Code)
	require.NotEqual(t, old.Value, sc.Value, "the change handed out a new cookie")

	for _, path := range []string{"/tunnels/status", "/dashboard"} {
		req := withCookie(t, path, &old)
		asHTMX(req)
		w := serve(s.h, req)
		assert.Equal(t, http.StatusSeeOther, w.Code, path)
		assert.Equal(t, "/login", w.Header().Get("Location"), "%s: still sent to the login page", path)
		assert.Nil(t, findCookie(w, "tunneld_session"), "%s: an htmx request does not clear the cookie", path)
	}
	assert.Equal(t, http.StatusOK, serve(s.h, withCookie(t, "/dashboard", sc)).Code, "the new cookie works")

	// A plain navigation with the old cookie clears it, as before.
	w := serve(s.h, withCookie(t, "/dashboard", &old))
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
	cleared := findCookie(w, "tunneld_session")
	require.NotNil(t, cleared, "a plain request clears the cookie of an unknown session")
	assert.Empty(t, cleared.Value)
	assert.Negative(t, cleared.MaxAge)
}

// dbtestFailDeletes is dbtest.FailDeletes on the stack's pool.
func dbtestFailDeletes(t *testing.T, s *stack, table string) func() {
	t.Helper()
	return dbtest.FailDeletes(t, s.pool, table)
}

// The admin's re-entry shares the helper of the settings page: it counts
// against the per-address limit too, not only against the account's.
func TestAdminReentryCountsAgainstThePerAddressLimit(t *testing.T) {
	e := newAdminTestEnv(t, func(o *Options) { o.LoginFailuresPerIP = 2 })
	target := e.insertUser(t, "target@example.com", true)
	promote := "/admin/users/" + itoa(target) + "/promote"
	lim := e.h.(*frontendHandler).limiters
	ipKey := sourceKey(clientIP(httptest.NewRequest(http.MethodGet, "/", nil))) // httptest's default peer

	require.Equal(t, http.StatusForbidden, e.post(t, e.adminCookie, promote, url.Values{"current_password": {"wrong-1"}}).Code)
	require.Equal(t, 1, lim.loginIP.count(ipKey))
	require.Equal(t, http.StatusForbidden, e.post(t, e.adminCookie, promote, url.Values{"current_password": {"wrong-2"}}).Code)

	w := e.post(t, e.adminCookie, promote, url.Values{"current_password": {adminTestPassword}})
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	// The per-address limit refused, possibly filled by others behind the
	// same address: the text does not blame the admin's account.
	assert.Contains(t, w.Body.String(), "Too many failed password attempts. Try again later. Nothing was changed.")
	assert.NotContains(t, w.Body.String(), "for your account")
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	u, err := e.users.FindByID(context.Background(), target)
	require.NoError(t, err)
	assert.False(t, u.IsAdmin)
}
