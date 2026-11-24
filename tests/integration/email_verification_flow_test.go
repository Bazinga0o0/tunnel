package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend"
	"github.com/Bazinga0o0/tunnel/internal/server/mail"
	"github.com/Bazinga0o0/tunnel/internal/server/passwordreset"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
	"github.com/Bazinga0o0/tunnel/internal/server/verifications"
)

// TestEmailVerificationFlow exercises the end-to-end signup -> verify-email
// journey against a real Postgres. It checks that before verification the
// dashboard shows the banner and POST /tokens is gated, and that after
// clicking the captured verification link the banner is gone and token
// creation succeeds.
func TestEmailVerificationFlow(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()

	userSvc := users.NewService(pool)
	sessSvc := sessions.NewService(pool)
	tm := newSignalMailer()
	verSvc := verifications.NewService(pool, userSvc)
	resetSvc := passwordreset.NewService(pool, userSvc, sessSvc)

	fe := frontend.New(frontend.Options{
		Domain:        "localhost",
		Users:         userSvc,
		Tokens:        tokens.NewService(pool),
		Reservations:  reservations.NewService(pool),
		Sessions:      sessSvc,
		Registry:      registry.New(),
		CSRFKey:       []byte("0123456789abcdef0123456789abcdef"),
		CSRFSecure:    false,
		Mailer:        tm,
		Verifications: verSvc,
		PasswordReset: resetSvc,
		PublicBaseURL: "https://app.localhost",
	})
	closeFrontendAtCleanup(t, fe)
	ts := httptest.NewServer(fe)
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}

	getCSRF := func(path string) string {
		t.Helper()
		res, err := client.Get(ts.URL + path)
		require.NoError(t, err)
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		const marker = `name="gorilla.csrf.Token" value="`
		i := strings.Index(string(body), marker)
		require.NotEqual(t, -1, i, "csrf token missing on %s", path)
		rest := string(body[i+len(marker):])
		end := strings.IndexByte(rest, '"')
		require.NotEqual(t, -1, end)
		return rest[:end]
	}

	// 1. Signup -> captures verify email.
	csrf := getCSRF("/signup")
	form := url.Values{
		"email":              {"v@example.com"},
		"password":           {"hunter222"},
		"gorilla.csrf.Token": {csrf},
	}
	res, err := client.PostForm(ts.URL+"/signup", form)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	require.Equal(t, "/login?signup=1", res.Header.Get("Location"))

	// Signup does not log in; the user logs in with the new account.
	csrf = getCSRF("/login")
	res, err = client.PostForm(ts.URL+"/login", url.Values{
		"email":              {"v@example.com"},
		"password":           {"hunter222"},
		"gorilla.csrf.Token": {csrf},
	})
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	require.Equal(t, "/dashboard", res.Header.Get("Location"))

	// Mail goes out in the background; wait for it.
	tm.next(t)
	sent := tm.Sent()
	require.Len(t, sent, 1)
	require.Contains(t, sent[0].Subject, "Verify")
	rawToken := extractToken(t, sent[0].TextBody)

	// 2. Dashboard shows "verify" banner before verification.
	res, err = client.Get(ts.URL + "/dashboard")
	require.NoError(t, err)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, string(body), "Please verify your email")

	// 3. POST /tokens should be blocked while unverified.
	csrf = getCSRF("/tokens")
	form = url.Values{"name": {"laptop"}, "gorilla.csrf.Token": {csrf}}
	res, err = client.PostForm(ts.URL+"/tokens", form)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	assert.Contains(t, res.Header.Get("Location"), "needs_verification")

	// 4. Click the verify link: it opens a confirmation page and verifies
	//    nothing yet (a mail scanner fetching the link must not verify).
	res, err = client.Get(ts.URL + "/verify?token=" + url.QueryEscape(rawToken))
	require.NoError(t, err)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, string(body), `action="/verify"`)
	u, err := userSvc.FindByEmail(context.Background(), "v@example.com")
	require.NoError(t, err)
	require.False(t, u.EmailVerifiedAt.Valid, "opening the link must not verify")

	// 4b. Confirm on that page.
	csrf = getCSRF("/verify?token=" + url.QueryEscape(rawToken))
	res, err = client.PostForm(ts.URL+"/verify", url.Values{
		"token":              {rawToken},
		"gorilla.csrf.Token": {csrf},
	})
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	assert.Contains(t, res.Header.Get("Location"), "/dashboard?verified=1")

	// 5. Dashboard no longer shows the unverified banner; shows the
	//    "Email verified" flash.
	res, err = client.Get(ts.URL + "/dashboard?verified=1")
	require.NoError(t, err)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	assert.NotContains(t, string(body), "Please verify your email")
	assert.Contains(t, string(body), "Email verified")

	// 6. POST /tokens now succeeds.
	csrf = getCSRF("/tokens")
	form = url.Values{"name": {"laptop"}, "gorilla.csrf.Token": {csrf}}
	res, err = client.PostForm(ts.URL+"/tokens", form)
	require.NoError(t, err)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, string(body), "twbl_")
}

// extractToken pulls the value after "token=" out of a plaintext email body
// (up to the next whitespace). Shared between the verification and
// password-reset flow tests.
func extractToken(t *testing.T, text string) string {
	t.Helper()
	idx := strings.Index(text, "token=")
	require.NotEqual(t, -1, idx)
	rest := text[idx+len("token="):]
	end := strings.IndexAny(rest, " \r\n")
	if end == -1 {
		end = len(rest)
	}
	return strings.TrimSpace(rest[:end])
}

// signalMailer is a TestMailer that also reports every message it got on a
// channel. The frontend sends mail in the background, so a test waits for
// the message with next before it looks at Sent.
type signalMailer struct {
	*mail.TestMailer
	sent chan mail.Message
}

func newSignalMailer() *signalMailer {
	return &signalMailer{TestMailer: mail.NewTestMailer(), sent: make(chan mail.Message, 64)}
}

func (m *signalMailer) Send(ctx context.Context, msg mail.Message) error {
	err := m.TestMailer.Send(ctx, msg)
	m.sent <- msg
	return err
}

// next waits for the next message that was handed to the mailer. The limit
// only ends a test that went wrong; the message normally comes at once.
func (m *signalMailer) next(t *testing.T) mail.Message {
	t.Helper()
	select {
	case msg := <-m.sent:
		return msg
	case <-time.After(10 * time.Second):
		t.Fatal("no mail was sent within 10 s")
		return mail.Message{}
	}
}

// closeFrontendAtCleanup stops the frontend's background mail sender when
// the test ends, through the method a server calls at shutdown.
func closeFrontendAtCleanup(t *testing.T, fe http.Handler) {
	t.Helper()
	c, ok := fe.(interface{ Close(context.Context) error })
	require.True(t, ok, "the frontend handler has a Close method")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		assert.NoError(t, c.Close(ctx))
	})
}
