package frontend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyLinkOpensAConfirmationPageAndPOSTVerifies(t *testing.T) {
	s := newStack(t, withMail)
	doSignup(t, s.h, "confirm@example.com", "pw12345678")
	sent := s.mailer.Sent()
	require.Len(t, sent, 1)
	raw := extractVerifyToken(t, sent[0])
	link := "/verify?token=" + url.QueryEscape(raw)

	verified := func() bool {
		u, err := s.users.FindByEmail(context.Background(), "confirm@example.com")
		require.NoError(t, err)
		return u.EmailVerifiedAt.Valid
	}

	// Opening the link (what a mail scanner or a link preview also does)
	// shows a page with a form and uses nothing up.
	for i := 0; i < 2; i++ {
		w := serve(s.h, httptest.NewRequest(http.MethodGet, link, nil))
		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, `method="post"`)
		assert.Contains(t, body, `action="/verify"`)
		assert.Contains(t, body, `name="token" value="`+raw+`"`)
		assert.Contains(t, body, `name="gorilla.csrf.Token"`)
		assert.Contains(t, w.Header().Get("Cache-Control"), "no-store", "the page carries the token")
		assert.False(t, verified(), "GET must not verify (request %d)", i+1)
	}

	// A POST without the CSRF token is refused.
	req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(url.Values{"token": {raw}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.Equal(t, http.StatusForbidden, serve(s.h, req).Code)
	assert.False(t, verified())

	// The form of the page verifies.
	token, csrfCookie := csrfFrom(t, s.h, link, "_gorilla_csrf")
	post := func() *httptest.ResponseRecorder {
		form := url.Values{"token": {raw}, "gorilla.csrf.Token": {token}}
		req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrfCookie)
		return serve(s.h, req)
	}
	w := post()
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/dashboard?verified=1", w.Header().Get("Location"))
	assert.True(t, verified())

	// The link is used up.
	w = post()
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid or has expired")
	w = serve(s.h, httptest.NewRequest(http.MethodGet, link, nil))
	assert.Contains(t, w.Body.String(), "invalid or has expired")
	assert.NotContains(t, w.Body.String(), `action="/verify"`, "no form for a dead link")
}

func TestVerifyWithoutToken(t *testing.T) {
	s := newStack(t, withMail)
	w := serve(s.h, httptest.NewRequest(http.MethodGet, "/verify", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "missing token")
	assert.NotContains(t, w.Body.String(), `action="/verify"`)

	w = postFormFrom(t, s.h, nil, "/verify", url.Values{}, "")
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "missing token")
}
