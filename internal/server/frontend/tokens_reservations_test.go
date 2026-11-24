package frontend

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
)

// fakeTunnelSession stands in for a tunnel session in the registry: it has
// an owner, the token it authenticated with, and counts how often it was
// closed.
type fakeTunnelSession struct {
	id      string
	userID  int64
	tokenID int64
	closed  atomic.Int32
}

func (f *fakeTunnelSession) ID() string          { return f.id }
func (f *fakeTunnelSession) UserIDValue() int64  { return f.userID }
func (f *fakeTunnelSession) TokenIDValue() int64 { return f.tokenID }
func (f *fakeTunnelSession) Close() error        { f.closed.Add(1); return nil }

func (s *stack) userID(t *testing.T, email string) int64 {
	t.Helper()
	u, err := s.users.FindByEmail(context.Background(), email)
	require.NoError(t, err)
	return u.ID
}

// tokenIDByName returns the ID of the user's active token with the name.
func (s *stack) tokenIDByName(t *testing.T, userID int64, name string) int64 {
	t.Helper()
	rows, err := s.tokens.ListActiveByUser(context.Background(), userID)
	require.NoError(t, err)
	for _, r := range rows {
		if r.Name == name {
			return r.ID
		}
	}
	t.Fatalf("no active token %q for user %d", name, userID)
	return 0
}

func TestRevokingATokenClosesItsTunnelSessions(t *testing.T) {
	s := newStack(t)
	scA := doSignup(t, s.h, "alice@example.com", "pw12345678")
	scB := doSignup(t, s.h, "bob@example.com", "pw12345678")
	alice, bob := s.userID(t, "alice@example.com"), s.userID(t, "bob@example.com")

	for _, name := range []string{"laptop", "server"} {
		require.Equal(t, http.StatusOK, s.post(t, "", "/tokens", url.Values{"name": {name}}, scA).Code)
	}
	require.Equal(t, http.StatusOK, s.post(t, "", "/tokens", url.Values{"name": {"bobs"}}, scB).Code)
	laptop := s.tokenIDByName(t, alice, "laptop")
	server := s.tokenIDByName(t, alice, "server")
	bobs := s.tokenIDByName(t, bob, "bobs")

	idle := &fakeTunnelSession{id: "laptop-idle", userID: alice, tokenID: laptop}
	withTunnel := &fakeTunnelSession{id: "laptop-http", userID: alice, tokenID: laptop}
	other := &fakeTunnelSession{id: "server", userID: alice, tokenID: server}
	bobsSession := &fakeTunnelSession{id: "bob", userID: bob, tokenID: bobs}
	require.NoError(t, s.reg.AddSession(idle, registry.SessionLimits{}))
	require.NoError(t, s.reg.RegisterHTTP("alpha", withTunnel))
	require.NoError(t, s.reg.AddSession(other, registry.SessionLimits{}))
	require.NoError(t, s.reg.AddSession(bobsSession, registry.SessionLimits{}))

	revoke := func(sc *http.Cookie, id int64) *httptest.ResponseRecorder {
		return postHTMX(t, s.h, sc, "/tokens", fmt.Sprintf("/tokens/%d/revoke", id))
	}

	// Somebody else's token is "not found", like a token that does not
	// exist, and nothing happens to it or its sessions.
	require.Equal(t, http.StatusNotFound, revoke(scB, laptop).Code)
	require.Equal(t, http.StatusNotFound, revoke(scA, 999999).Code)
	assert.Zero(t, idle.closed.Load())
	assert.Zero(t, withTunnel.closed.Load())
	s.tokenIDByName(t, alice, "laptop") // still active

	// The owner revokes: every session of that token ends.
	require.Equal(t, http.StatusOK, revoke(scA, laptop).Code)
	assert.EqualValues(t, 1, idle.closed.Load())
	assert.EqualValues(t, 1, withTunnel.closed.Load())
	_, routed := s.reg.LookupHTTP("alpha")
	assert.False(t, routed, "the tunnel of the revoked token is gone")
	assert.Zero(t, other.closed.Load(), "a session of another token stays")
	assert.Zero(t, bobsSession.closed.Load(), "a session of another user stays")

	// A second revoke finds nothing.
	require.Equal(t, http.StatusNotFound, revoke(scA, laptop).Code)
	assert.EqualValues(t, 1, idle.closed.Load())

	w := postHTMX(t, s.h, scA, "/tokens", "/tokens/not-a-number/revoke")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTokenErrorsAreFieldErrors(t *testing.T) {
	s := newStack(t, func(o *Options, s *stack) {
		o.Tokens = tokens.NewServiceWithOptions(s.pool, tokens.Options{MaxActivePerUser: 1})
	})
	sc := doSignup(t, s.h, "limits@example.com", "pw12345678")
	create := func(name string) *httptest.ResponseRecorder {
		return s.post(t, "", "/tokens", url.Values{"name": {name}}, sc)
	}
	oobError := regexp.MustCompile(`<div id="token-error" hx-swap-oob="outerHTML"[^>]*>([^<]*)</div>`)

	w := create("first")
	require.Equal(t, http.StatusOK, w.Code)
	m := oobError.FindStringSubmatch(w.Body.String())
	require.NotNil(t, m, "success clears the error field: %s", w.Body.String())
	assert.Empty(t, strings.TrimSpace(m[1]))

	for _, c := range []struct{ name, want string }{
		{"second", "maximum number of active tokens"},
		{strings.Repeat("n", 65), "too long"},
		{"   ", "Enter a name"},
	} {
		w = create(c.name)
		require.Equal(t, http.StatusUnprocessableEntity, w.Code, c.name)
		m = oobError.FindStringSubmatch(w.Body.String())
		require.NotNil(t, m, "the error goes to the field: %s", w.Body.String())
		assert.Contains(t, m[1], c.want)
		assert.NotContains(t, w.Body.String(), "twbl_", "no token")
	}

	// The page has the element the errors go to, and htmx swaps 422.
	req := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	req.AddCookie(sc)
	w = serve(s.h, req)
	assert.Contains(t, w.Body.String(), `id="token-error"`)
	assert.Regexp(t, `name="htmx-config" content="[^"]*422`, w.Body.String())
}

func TestTokenBannerShowsTheNewToken(t *testing.T) {
	s := newStack(t)
	sc := doSignup(t, s.h, "banner@example.com", "pw12345678")
	w := s.post(t, "", "/tokens", url.Values{"name": {`<b>"quoted"</b>`}}, sc)
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Regexp(t, `hx-swap-oob="afterbegin:main"`, body)
	assert.Regexp(t, `<code[^>]*>twbl_[0-9A-Za-z]+</code>`, body)
	assert.NotContains(t, body, `<b>"quoted"</b>`, "the name is escaped")
	assert.Contains(t, body, "&lt;b&gt;")
}

func TestExpiredTokensAreShownAsExpired(t *testing.T) {
	s := newStack(t)
	sc := doSignup(t, s.h, "expiry@example.com", "pw12345678")
	uid := s.userID(t, "expiry@example.com")
	for _, name := range []string{"old-token", "new-token"} {
		require.Equal(t, http.StatusOK, s.post(t, "", "/tokens", url.Values{"name": {name}}, sc).Code)
	}
	_, err := s.pool.Exec(context.Background(),
		`UPDATE api_tokens SET expires_at = now() - interval '1 hour' WHERE id = $1`, s.tokenIDByName(t, uid, "old-token"))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	req.AddCookie(sc)
	w := serve(s.h, req)
	require.Equal(t, http.StatusOK, w.Code)
	rowOf := func(name string) string {
		for _, seg := range strings.Split(w.Body.String(), "</tr>") {
			if strings.Contains(seg, name) {
				return seg[strings.LastIndex(seg, "<tr"):]
			}
		}
		t.Fatalf("no row for %s", name)
		return ""
	}
	assert.Contains(t, rowOf("old-token"), "expired")
	assert.NotContains(t, rowOf("new-token"), "expired")
}

func TestReservationErrorsAreFieldErrors(t *testing.T) {
	s := newStack(t, func(o *Options, s *stack) {
		o.Reservations = reservations.NewServiceWithOptions(s.pool, reservations.Options{MaxSubdomainsPerUser: 2})
	})
	scA := doSignup(t, s.h, "res-a@example.com", "pw12345678")
	scB := doSignup(t, s.h, "res-b@example.com", "pw12345678")
	reserve := func(sc *http.Cookie, name string) *httptest.ResponseRecorder {
		return s.post(t, "", "/reservations", url.Values{"subdomain": {name}}, sc)
	}
	oobError := regexp.MustCompile(`<div id="reservation-error" hx-swap-oob="outerHTML"[^>]*>([^<]*)</div>`)

	w := reserve(scA, "one")
	require.Equal(t, http.StatusOK, w.Code)
	m := oobError.FindStringSubmatch(w.Body.String())
	require.NotNil(t, m)
	assert.Empty(t, strings.TrimSpace(m[1]), "success clears the error field")
	assert.NotRegexp(t, `<div id="reservation-error" hx-swap-oob="outerHTML" class="[^"]*bg-red-100`, w.Body.String(),
		"the cleared field is not a red box")

	w = reserve(scA, "  Two ")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "two.tunnel.localhost", "names are normalised")

	for _, c := range []struct {
		sc         *http.Cookie
		name, want string
	}{
		{scA, "three", "maximum number of reserved subdomains"},
		{scB, "admin", "reserved for system use"},
		{scB, "Has_Underscore", "lowercase letters"},
		{scB, "ab", "lowercase letters"},
		{scB, "one", "already reserved"},
		{scB, "TWO", "already reserved"},
	} {
		w = reserve(c.sc, c.name)
		require.Equal(t, http.StatusUnprocessableEntity, w.Code, c.name)
		m = oobError.FindStringSubmatch(w.Body.String())
		require.NotNil(t, m, "%s: the error goes to the field: %s", c.name, w.Body.String())
		assert.Contains(t, m[1], c.want, c.name)
	}
}

func TestReservingANameEndsOtherUsersTunnelsOnIt(t *testing.T) {
	s := newStack(t)
	scA := doSignup(t, s.h, "owner@example.com", "pw12345678")
	doSignup(t, s.h, "squatter@example.com", "pw12345678")
	owner, squatter := s.userID(t, "owner@example.com"), s.userID(t, "squatter@example.com")

	foreign := &fakeTunnelSession{id: "squat", userID: squatter, tokenID: 1}
	own := &fakeTunnelSession{id: "own", userID: owner, tokenID: 2}
	anonymous := &fakeTunnelSession{id: "static", userID: 0, tokenID: 0}
	require.NoError(t, s.reg.RegisterHTTP("shared", foreign))
	require.NoError(t, s.reg.RegisterHTTP("mine", own))
	require.NoError(t, s.reg.RegisterHTTP("nobody", anonymous))

	for _, name := range []string{"shared", "mine", "nobody"} {
		require.Equal(t, http.StatusOK, s.post(t, "", "/reservations", url.Values{"subdomain": {name}}, scA).Code, name)
	}
	assert.EqualValues(t, 1, foreign.closed.Load(), "another user's tunnel on the name ends")
	_, routed := s.reg.LookupHTTP("shared")
	assert.False(t, routed)
	assert.Zero(t, own.closed.Load(), "the owner's own tunnel stays")
	_, routed = s.reg.LookupHTTP("mine")
	assert.True(t, routed)
	assert.EqualValues(t, 1, anonymous.closed.Load(), "a session without a user is foreign too")
}
