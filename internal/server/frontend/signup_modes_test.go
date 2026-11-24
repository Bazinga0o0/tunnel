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
)

// withSignupMode sets Options.SignupMode.
func withSignupMode(mode string) func(*Options, *stack) {
	return func(o *Options, _ *stack) { o.SignupMode = mode }
}

func TestHoneypotCreatesNothing(t *testing.T) {
	s := newStack(t, withMail, withAudit)

	// The form carries the field under a name that autofill leaves alone
	// ("website" is filled in by some browsers and password managers).
	page := httptest.NewRecorder()
	s.h.ServeHTTP(page, httptest.NewRequest("GET", "/signup", nil))
	require.Equal(t, http.StatusOK, page.Code)
	assert.Contains(t, page.Body.String(), `name="hp_field_x" value="" tabindex="-1" autocomplete="off"`)
	assert.NotContains(t, page.Body.String(), `name="website"`)

	w := s.post(t, nextPeer(), "/signup", url.Values{
		"email":      {"bot@example.com"},
		"password":   {"pw12345678"},
		"hp_field_x": {"x"},
	}, nil)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login?signup=1", w.Header().Get("Location"))

	n, err := s.users.CountAll(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n, "no account")
	assert.Empty(t, s.mailer.Sent(), "no mail")

	rows := s.auditRows(t)
	require.Len(t, rows, 1)
	assert.Equal(t, "auth.signup.honeypot", rows[0].Action)
	assert.Nil(t, rows[0].UserID)
}

func TestClosedSignup(t *testing.T) {
	s := newStack(t, withMail, withSignupMode("closed"))

	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}

	w := get("/signup")
	require.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Registrierung geschlossen")
	assert.NotContains(t, w.Body.String(), `action="/signup"`)

	w = s.post(t, nextPeer(), "/signup", url.Values{
		"email":    {"new@example.com"},
		"password": {"pw12345678"},
	}, nil)
	require.Equal(t, http.StatusNotFound, w.Code)

	n, err := s.users.CountAll(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n, "no account")
	assert.Empty(t, s.mailer.Sent(), "no mail")

	w = get("/login")
	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), `href="/signup"`)
}

func TestVerifyNotifiesAdminsWhenPending(t *testing.T) {
	s := newStack(t, withMail, withSignupMode("approval"))
	ctx := context.Background()
	adminID := dbtest.InsertUser(t, s.pool, "admin@example.com")
	require.NoError(t, s.users.Promote(ctx, adminID))
	require.NoError(t, s.users.Approve(ctx, adminID))

	doSignup(t, s.h, "pending@example.com", "pw12345678")
	sent := s.mailer.Sent()
	require.Len(t, sent, 1, "the verification mail")
	raw := extractVerifyToken(t, sent[0])
	s.mailer.Reset()

	w := confirmVerification(t, s.h, raw)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/dashboard?verified=1", w.Header().Get("Location"))
	drainMail(t, s.h)

	sent = s.mailer.Sent()
	require.Len(t, sent, 1, "one mail to the one admin")
	assert.Equal(t, "admin@example.com", sent[0].To)
	assert.Contains(t, sent[0].TextBody, "https://app.tunnel.localhost/admin/approvals")
	assert.Contains(t, sent[0].HTMLBody, `href="https://app.tunnel.localhost/admin/approvals"`)
	assert.Contains(t, sent[0].TextBody, "pending@example.com")
}
