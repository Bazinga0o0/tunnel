package integration

import (
	"context"
	"crypto/tls"
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

	"github.com/Bazinga0o0/tunnel/internal/client/dialer"
	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// TestFrontendFullFlow boots frontend + acceptor against real Postgres and
// walks through the complete user journey end-to-end.
func TestFrontendFullFlow(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()

	userSvc := users.NewService(pool)
	tokenSvc := tokens.NewService(pool)
	resSvc := reservations.NewService(pool)
	sessSvc := sessions.NewService(pool)
	reg := registry.New()

	// --- Boot frontend ---
	// CSRFSecure: false because httptest uses plaintext; the frontend already
	// marks these as plaintext via csrf.PlaintextHTTPRequest when !CSRFSecure.
	csrfKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes, deterministic for tests
	fe := frontend.New(frontend.Options{
		Domain:       "localhost",
		Users:        userSvc,
		Tokens:       tokenSvc,
		Reservations: resSvc,
		Sessions:     sessSvc,
		Registry:     reg,
		CSRFKey:      csrfKey,
		CSRFSecure:   false,
	})
	closeFrontendAtCleanup(t, fe)
	feServer := httptest.NewServer(fe)
	defer feServer.Close()

	// --- Boot acceptor (tunnel control plane) ---
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	acc := acceptor.New(acceptor.Options{
		Domain:       "localhost",
		Registry:     reg,
		DBVerifier:   auth.NewDBVerifier(tokenSvc),
		Reservations: resSvc,
	})
	tunLn, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	require.NoError(t, err)
	defer tunLn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go acc.Serve(ctx, tunLn)

	// --- HTTP client with cookie jar so we keep the session cookie ---
	jar, _ := cookiejar.New(nil)
	httpc := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects — we want to assert Location headers.
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}

	// Helper: fetch CSRF token+cookie from a GET page.
	getCSRF := func(t *testing.T, path string) string {
		t.Helper()
		res, err := httpc.Get(feServer.URL + path)
		require.NoError(t, err)
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		const marker = `name="gorilla.csrf.Token" value="`
		idx := strings.Index(string(body), marker)
		require.NotEqual(t, -1, idx, "csrf token missing on %s", path)
		rest := string(body[idx+len(marker):])
		end := strings.IndexByte(rest, '"')
		require.NotEqual(t, -1, end)
		return rest[:end]
	}

	// --- 1. GET /login (unauthed) should succeed ---
	res, err := httpc.Get(feServer.URL + "/login")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)
	res.Body.Close()

	// --- 2. Sign up ---
	csrf := getCSRF(t, "/signup")
	form := url.Values{
		"email":              {"e2e@example.com"},
		"password":           {"hunter222"},
		"gorilla.csrf.Token": {csrf},
	}
	res, err = httpc.PostForm(feServer.URL+"/signup", form)
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	// Signup does not log in: its answer must not differ for an address
	// that already has an account.
	assert.Equal(t, "/login?signup=1", res.Header.Get("Location"))
	res.Body.Close()

	// --- 2b. Log in ---
	csrf = getCSRF(t, "/login")
	form = url.Values{
		"email":              {"e2e@example.com"},
		"password":           {"hunter222"},
		"gorilla.csrf.Token": {csrf},
	}
	res, err = httpc.PostForm(feServer.URL+"/login", form)
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	assert.Equal(t, "/dashboard", res.Header.Get("Location"))
	res.Body.Close()

	// --- 3. GET /dashboard with session ---
	res, err = httpc.Get(feServer.URL + "/dashboard")
	require.NoError(t, err)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, string(body), "e2e@example.com")

	// --- 4. Create an API token via the tokens page ---
	csrf = getCSRF(t, "/tokens")
	form = url.Values{
		"name":               {"e2e-laptop"},
		"gorilla.csrf.Token": {csrf},
	}
	res, err = httpc.PostForm(feServer.URL+"/tokens", form)
	require.NoError(t, err)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	// Extract the raw token from the response body — it appears inside a
	// <code> tag in the banner fragment.
	s := string(body)
	const tokMarker = "twbl_"
	idx := strings.Index(s, tokMarker)
	require.NotEqual(t, -1, idx, "raw token not found in /tokens response")
	end := idx + len(tokMarker)
	for end < len(s) && isTokenChar(s[end]) {
		end++
	}
	rawToken := s[idx:end]
	require.True(t, strings.HasPrefix(rawToken, "twbl_"), "token must start with twbl_: got %q", rawToken)
	require.Greater(t, len(rawToken), 10, "token too short: %q", rawToken)

	// --- 5. Use the token to open a real tunnel ---
	tunAddr := tunLn.Addr().String()
	d := dialer.New(dialer.Options{
		ServerAddr:         tunAddr,
		Token:              rawToken,
		InsecureSkipVerify: true,
	})
	sess, err := d.Dial(ctx)
	require.NoError(t, err)
	defer sess.Close()

	ack, err := sess.RegisterHTTP(ctx, "e2eapp")
	require.NoError(t, err)
	require.Equal(t, "e2eapp", ack.Subdomain)

	// Give the registry a moment to receive the session.
	require.Eventually(t, func() bool {
		_, ok := reg.LookupHTTP("e2eapp")
		return ok
	}, 2*time.Second, 20*time.Millisecond)

	// --- 6. /tunnels/status shows the tunnel ---
	res, err = httpc.Get(feServer.URL + "/tunnels/status")
	require.NoError(t, err)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, string(body), "e2eapp")

	// --- 7. Change password ---
	csrf = getCSRF(t, "/settings")
	form = url.Values{
		"current":            {"hunter222"},
		"new":                {"newpassword1"},
		"confirm":            {"newpassword1"},
		"gorilla.csrf.Token": {csrf},
	}
	res, err = httpc.PostForm(feServer.URL+"/settings/password", form)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	assert.Equal(t, "/settings?changed=1", res.Header.Get("Location"))

	// --- 8. Logout ---
	csrf = getCSRF(t, "/dashboard")
	form = url.Values{"gorilla.csrf.Token": {csrf}}
	res, err = httpc.PostForm(feServer.URL+"/logout", form)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	assert.Equal(t, "/login", res.Header.Get("Location"))

	// --- 9. After logout, /dashboard should redirect to /login ---
	res, err = httpc.Get(feServer.URL + "/dashboard")
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	assert.Contains(t, res.Header.Get("Location"), "/login")
}

func isTokenChar(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '_'
}
