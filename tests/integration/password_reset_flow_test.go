package integration

import (
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
	"github.com/Bazinga0o0/tunnel/internal/server/passwordreset"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
	"github.com/Bazinga0o0/tunnel/internal/server/verifications"
)

// TestPasswordResetFlow walks through the forgot-password journey end-to-end:
// signup -> forgot -> captured reset mail -> consume token -> old password
// fails -> new password works.
func TestPasswordResetFlow(t *testing.T) {
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

	// 1. Signup.
	csrf := getCSRF("/signup")
	form := url.Values{
		"email":              {"r@example.com"},
		"password":           {"initialpw1"},
		"gorilla.csrf.Token": {csrf},
	}
	res, err := client.PostForm(ts.URL+"/signup", form)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	require.Equal(t, "/login?signup=1", res.Header.Get("Location"))

	// Drop the verification email captured on signup so the mailer snapshot
	// after /forgot-password is easy to assert on.
	tm.next(t) // the verification mail, sent in the background
	tm.Reset()

	// 2. Signup does not log in, so nobody is logged in for the reset.

	// 3. Request reset.
	csrf = getCSRF("/forgot-password")
	form = url.Values{
		"email":              {"r@example.com"},
		"gorilla.csrf.Token": {csrf},
	}
	res, err = client.PostForm(ts.URL+"/forgot-password", form)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	tm.next(t)
	sent := tm.Sent()
	require.Len(t, sent, 1)
	require.Contains(t, sent[0].Subject, "Reset")
	rawToken := extractToken(t, sent[0].TextBody)

	// 4. Submit new password.
	csrf = getCSRF("/reset?token=" + url.QueryEscape(rawToken))
	form = url.Values{
		"token":              {rawToken},
		"new":                {"betterpw5678"},
		"confirm":            {"betterpw5678"},
		"gorilla.csrf.Token": {csrf},
	}
	res, err = client.PostForm(ts.URL+"/reset", form)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	assert.Equal(t, "/login?reset=1", res.Header.Get("Location"))

	// 5. Old password fails.
	csrf = getCSRF("/login")
	form = url.Values{
		"email":              {"r@example.com"},
		"password":           {"initialpw1"},
		"gorilla.csrf.Token": {csrf},
	}
	res, err = client.PostForm(ts.URL+"/login", form)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)

	// 6. New password works.
	csrf = getCSRF("/login")
	form = url.Values{
		"email":              {"r@example.com"},
		"password":           {"betterpw5678"},
		"gorilla.csrf.Token": {csrf},
	}
	res, err = client.PostForm(ts.URL+"/login", form)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	assert.Equal(t, "/dashboard", res.Header.Get("Location"))
}
