package frontend

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An account with an unverified address can still take back what it holds:
// revoking a token and releasing a reservation need a login only. Creating
// stays behind the verified-address gate.
func TestUnverifiedUsersCanRevokeAndRelease(t *testing.T) {
	s := newStack(t, withMail) // withMail switches the verified-address gate on
	sc := doSignup(t, s.h, "unverified@example.com", "pw12345678")
	uid := s.userID(t, "unverified@example.com")
	ctx := context.Background()

	// What an operator gave the account (create-user, issue-token, a grant).
	_, tok, err := s.tokens.Issue(ctx, uid, "from-the-cli")
	require.NoError(t, err)
	require.NoError(t, s.res.Reserve(ctx, "kept-name", uid))

	w := postHTMX(t, s.h, sc, "/tokens", fmt.Sprintf("/tokens/%d/revoke", tok.ID))
	require.Equal(t, http.StatusOK, w.Code, "revoke: %s", w.Body.String())
	active, err := s.tokens.ListActiveByUser(ctx, uid)
	require.NoError(t, err)
	assert.Empty(t, active, "the token is revoked")

	w = postHTMX(t, s.h, sc, "/reservations", "/reservations/kept-name/release")
	require.Equal(t, http.StatusOK, w.Code, "release: %s", w.Body.String())
	_, reserved, err := s.res.Owner(ctx, "kept-name")
	require.NoError(t, err)
	assert.False(t, reserved, "the name is released")

	// Creating still needs a verified address.
	for path, form := range map[string]url.Values{
		"/tokens":       {"name": {"new-token"}},
		"/reservations": {"subdomain": {"new-name"}},
	} {
		w = s.post(t, "", path, form, sc)
		require.Equal(t, http.StatusSeeOther, w.Code, path)
		assert.Equal(t, "/dashboard?needs_verification=1", w.Header().Get("Location"), path)
	}
	active, err = s.tokens.ListActiveByUser(ctx, uid)
	require.NoError(t, err)
	assert.Empty(t, active, "nothing was created")

	// Without a login, revoke and release are still refused.
	w = postHTMX(t, s.h, nil, "/login", fmt.Sprintf("/tokens/%d/revoke", tok.ID))
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestUserActionsPerHourAreLimitedPerUser(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) { o.UserActionsPerHour = 4 })
	sc := doSignup(t, s.h, "busy-user@example.com", "pw12345678")
	other := doSignup(t, s.h, "other-user@example.com", "pw12345678")
	uid := s.userID(t, "busy-user@example.com")
	ctx := context.Background()

	// Each of the four mutating actions counts once.
	require.Equal(t, http.StatusOK, s.post(t, "", "/tokens", url.Values{"name": {"t1"}}, sc).Code)
	require.Equal(t, http.StatusOK, postHTMX(t, s.h, sc, "/tokens", fmt.Sprintf("/tokens/%d/revoke", s.tokenIDByName(t, uid, "t1"))).Code)
	require.Equal(t, http.StatusOK, s.post(t, "", "/reservations", url.Values{"subdomain": {"first-name"}}, sc).Code)
	require.Equal(t, http.StatusOK, postHTMX(t, s.h, sc, "/reservations", "/reservations/first-name/release").Code)
	require.Equal(t, 4, limitersOf(t, s.h).userActions.count(userActionKey(uid)))

	// The fifth of any kind is refused, and does nothing.
	for _, try := range []struct {
		name string
		send func() int
	}{
		{"create token", func() int { return s.post(t, "", "/tokens", url.Values{"name": {"t2"}}, sc).Code }},
		{"revoke token", func() int { return postHTMX(t, s.h, sc, "/tokens", "/tokens/1/revoke").Code }},
		{"reserve", func() int {
			return s.post(t, "", "/reservations", url.Values{"subdomain": {"second-name"}}, sc).Code
		}},
		{"release", func() int { return postHTMX(t, s.h, sc, "/reservations", "/reservations/first-name/release").Code }},
	} {
		assert.Equal(t, http.StatusTooManyRequests, try.send(), try.name)
	}
	w := s.post(t, "", "/tokens", url.Values{"name": {"t3"}}, sc)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Positive(t, retryAfterSeconds(t, w))
	assert.Contains(t, w.Body.String(), msgTooManyUserActions)
	active, err := s.tokens.ListActiveByUser(ctx, uid)
	require.NoError(t, err)
	assert.Empty(t, active, "no token was created over the limit")
	_, reserved, err := s.res.Owner(ctx, "second-name")
	require.NoError(t, err)
	assert.False(t, reserved, "no name was reserved over the limit")

	// Pages are not limited, nor is another user.
	assert.Equal(t, http.StatusOK, serve(s.h, withCookie(t, "/tokens", sc)).Code)
	assert.Equal(t, http.StatusOK, s.post(t, "", "/tokens", url.Values{"name": {"theirs"}}, other).Code)

	// After an hour the user may act again.
	s.clock.Advance(time.Hour + time.Second)
	assert.Equal(t, http.StatusOK, s.post(t, "", "/tokens", url.Values{"name": {"t4"}}, sc).Code)
}

func TestUserActionsPerHourOptions(t *testing.T) {
	rl := newRateLimiters(Options{})
	assert.Equal(t, 120, rl.userActions.limit, "default")
	assert.Equal(t, time.Hour, rl.userActions.window)
	assert.Equal(t, 9, newRateLimiters(Options{UserActionsPerHour: 9}).userActions.limit)
	assert.LessOrEqual(t, newRateLimiters(Options{UserActionsPerHour: -1}).userActions.limit, 0, "negative disables")
}

// withCookie builds a GET of path with the session cookie sc.
func withCookie(t *testing.T, path string, sc *http.Cookie) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(sc)
	return req
}

// asHTMX marks a request the way htmx marks the requests it sends.
func asHTMX(r *http.Request) { r.Header.Set("HX-Request", "true") }

// htmxSwaps reports, for each status, whether htmx would swap a response
// with that status under the htmx-config of page: as in htmx's
// responseHandling, the first rule whose code pattern matches the status
// decides.
func htmxSwaps(t *testing.T, page string, statuses ...int) map[int]bool {
	t.Helper()
	m := regexp.MustCompile(`<meta name="htmx-config" content="([^"]*)"`).FindStringSubmatch(page)
	require.NotNil(t, m, "the page configures htmx")
	var cfg struct {
		ResponseHandling []struct {
			Code string `json:"code"`
			Swap bool   `json:"swap"`
		} `json:"responseHandling"`
	}
	require.NoError(t, json.Unmarshal([]byte(html.UnescapeString(m[1])), &cfg))
	out := map[int]bool{}
	for _, status := range statuses {
		for _, rule := range cfg.ResponseHandling {
			if regexp.MustCompile(rule.Code).MatchString(strconv.Itoa(status)) {
				out[status] = rule.Swap
				break
			}
		}
	}
	return out
}

// Over the budget the refusal is readable in the browser: an htmx request
// gets the message in the error field of its page (out of band, 429 swapped
// by the page's htmx rule) and htmx is told to leave the rest of the page as
// it is, so the row of a revoke or release stays; a plain form post gets
// the message as text. Both keep 429 and Retry-After, and nothing happens.
func TestUserActionsOverTheLimitAreShownInThePage(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) { o.UserActionsPerHour = 1 })
	sc := doSignup(t, s.h, "limit-shown@example.com", "pw12345678")
	uid := s.userID(t, "limit-shown@example.com")
	ctx := context.Background()
	require.Equal(t, http.StatusOK, s.post(t, "", "/tokens", url.Values{"name": {"kept"}}, sc).Code)
	tokenID := s.tokenIDByName(t, uid, "kept")
	require.NoError(t, s.res.Reserve(ctx, "kept-name", uid)) // a grant: not counted

	tokenField := regexp.MustCompile(`^<div id="token-error" hx-swap-oob="outerHTML"[^>]*>([^<]*)</div>$`)
	reservationField := regexp.MustCompile(`^<div id="reservation-error" hx-swap-oob="outerHTML"[^>]*>([^<]*)</div>$`)
	actions := []struct {
		name, path string
		form       url.Values
		field      *regexp.Regexp
	}{
		{"create token", "/tokens", url.Values{"name": {"second"}}, tokenField},
		{"revoke token", fmt.Sprintf("/tokens/%d/revoke", tokenID), nil, tokenField},
		{"reserve", "/reservations", url.Values{"subdomain": {"second-name"}}, reservationField},
		{"release", "/reservations/kept-name/release", nil, reservationField},
	}
	for _, a := range actions {
		w := postFormFrom(t, s.h, sc, a.path, a.form, "", asHTMX)
		require.Equal(t, http.StatusTooManyRequests, w.Code, a.name)
		assert.Positive(t, retryAfterSeconds(t, w), a.name)
		assert.Equal(t, "none", w.Header().Get("HX-Reswap"), "%s: htmx leaves the row and the table alone", a.name)
		assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"), a.name)
		m := a.field.FindStringSubmatch(strings.TrimSpace(w.Body.String()))
		require.NotNil(t, m, "%s: the message goes to the error field of the page: %q", a.name, w.Body.String())
		assert.Equal(t, msgTooManyUserActions, m[1], a.name)
	}

	// Without htmx: the message as text, as before.
	for _, a := range actions {
		w := postFormFrom(t, s.h, sc, a.path, a.form, "")
		require.Equal(t, http.StatusTooManyRequests, w.Code, a.name)
		assert.Positive(t, retryAfterSeconds(t, w), a.name)
		assert.Empty(t, w.Header().Get("HX-Reswap"), a.name)
		assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"), a.name)
		assert.Equal(t, msgTooManyUserActions+"\n", w.Body.String(), a.name)
	}

	// Nothing was done.
	active, err := s.tokens.ListActiveByUser(ctx, uid)
	require.NoError(t, err)
	require.Len(t, active, 1)
	assert.Equal(t, "kept", active[0].Name)
	owner, reserved, err := s.res.Owner(ctx, "kept-name")
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, uid, owner)
	_, reserved, err = s.res.Owner(ctx, "second-name")
	require.NoError(t, err)
	assert.False(t, reserved)

	// Both pages tell htmx to swap a 429 and, as before, 2xx and 422 but no
	// other error.
	for page, field := range map[string]string{"/tokens": `<div id="token-error">`, "/reservations": `<div id="reservation-error">`} {
		w := serve(s.h, withCookie(t, page, sc))
		require.Equal(t, http.StatusOK, w.Code, page)
		assert.Contains(t, w.Body.String(), field, "%s has the field the message goes to", page)
		assert.Equal(t, map[int]bool{
			200: true, 204: false, 400: false, 403: false, 404: false, 413: false,
			422: true, 429: true, 500: false, 503: false,
		}, htmxSwaps(t, w.Body.String(), 200, 204, 400, 403, 404, 413, 422, 429, 500, 503), page)
	}
}
