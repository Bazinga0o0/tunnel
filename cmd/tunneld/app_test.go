package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

// The server assembled in database mode: every piece is connected the way
// serve connects it. Each assertion stands for a wiring line that, if it
// went missing, turns this test red.
func TestAppWiresTheDatabaseMode(t *testing.T) {
	pool := dbtest.Pool(t) // skips without TUNNELD_TEST_DATABASE_URL; empties the tables
	t.Cleanup(pool.Close)

	var hashCalls []auth.HashLimits
	prev := setHashLimits
	setHashLimits = func(l auth.HashLimits) { hashCalls = append(hashCalls, l) }
	t.Cleanup(func() { setHashLimits = prev })

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	cfg := loadConfig(t, fmt.Sprintf(`domain: tunnel.test
listen: {tunnel_addr: "127.0.0.1:0", http_addr: "127.0.0.1:0"}
tls: {self_signed_hosts: [tunnel.test, "*.tunnel.test"]}
auth: {csrf_key: %q}
database: {url: %q}
metrics: {addr: ""}
tunnel: {revalidate_interval: 1s}
limits: {hash_concurrency: 3, hash_wait: 7s, min_password_length: 9, max_tokens_per_user: 1}
`, key, os.Getenv("TUNNELD_TEST_DATABASE_URL")))

	logger, _ := captureLog()
	ctx, cancel := context.WithCancel(context.Background())
	a, err := newApp(ctx, cfg, logger)
	require.NoError(t, err)
	t.Cleanup(func() {
		cancel()
		_ = a.closeFrontend(5 * time.Second)
		a.closePool()
	})
	a.startBackground(ctx)

	// Hash limits from the config.
	assert.Equal(t, []auth.HashLimits{{MaxConcurrent: 3, MaxWait: 7 * time.Second}}, hashCalls)

	// The account services are the configured ones.
	_, err = a.users.Create(ctx, "short@example.com", "8chars!!")
	require.ErrorIs(t, err, users.ErrPasswordTooShort, "min_password_length 9")
	u, err := a.users.Create(ctx, "login@example.com", "a-good-password")
	require.NoError(t, err)
	raw, _, err := a.tokens.Issue(ctx, u.ID, "laptop")
	require.NoError(t, err)
	_, _, err = a.tokens.Issue(ctx, u.ID, "desktop")
	require.ErrorIs(t, err, tokens.ErrTooManyTokens, "max_tokens_per_user 1")

	// A login through the public listener writes an audit row.
	publicLn, err := listenPublic(testports.Loopback+":0", a.tlsConfig, cfg.HTTPServer, logger)
	require.NoError(t, err)
	go func() { _ = a.public.Serve(publicLn) }()
	t.Cleanup(func() { shutdownServer(a.public, time.Second) })
	loginThroughTheUI(t, publicLn.Addr().String(), "login@example.com", "a-good-password")
	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE action = 'auth.login.success' AND user_id = $1`, u.ID).Scan(&rows))
	assert.Equal(t, 1, rows, "the audit service reaches the web UI")

	// The revalidation runs: a token revoked behind the server's back ends
	// its tunnel.
	tunnelLn, err := tls.Listen("tcp", testports.Loopback+":0", a.tlsConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tunnelLn.Close() })
	go func() { _ = a.acceptor.Serve(ctx, tunnelLn) }()
	client := dialTunnel(t, tunnelLn.Addr().String(), raw)
	client.requireAlive(t, "before the revoke")
	_, err = pool.Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE user_id = $1`, u.ID)
	require.NoError(t, err)
	client.requireEnded(t, "token revoked in the database")
}

// At start in approval and closed mode the server approves the accounts in
// use, so that switching the mode locks out none of them; in open mode it
// leaves every account as it is.
func TestApproveExistingIfRequired(t *testing.T) {
	for _, c := range []struct {
		signup  string
		approve bool
	}{{"", false}, {"open", false}, {"approval", true}, {"closed", true}} {
		t.Run("signup="+c.signup, func(t *testing.T) {
			pool := dbtest.Pool(t)
			t.Cleanup(pool.Close)
			ctx := context.Background()
			userSvc := users.NewService(pool)
			admin := dbtest.InsertUser(t, pool, "admin@example.com")
			require.NoError(t, userSvc.Promote(ctx, admin))
			holder := dbtest.InsertUser(t, pool, "holder@example.com")
			_, err := pool.Exec(ctx, `INSERT INTO api_tokens (user_id, name, token_hash, token_prefix)
				VALUES ($1, 'laptop', '\x04', 'dddddddd')`, holder)
			require.NoError(t, err)
			bare := dbtest.InsertUser(t, pool, "bare@example.com")

			cfg := loadConfig(t, fullConfig)
			cfg.Auth.Signup = c.signup
			logger, logs := captureLog()
			n, err := approveExistingIfRequired(ctx, cfg, userSvc, logger)
			require.NoError(t, err)

			want := int64(0)
			if c.approve {
				want = 2
				assert.Contains(t, logs.String(), "signup approval: existing accounts approved")
				assert.Contains(t, logs.String(), "count=2")
			} else {
				assert.Empty(t, logs.String(), "nothing to log in open mode")
			}
			assert.Equal(t, want, n)
			for name, id := range map[string]int64{"admin": admin, "token holder": holder} {
				u, err := userSvc.FindByID(ctx, id)
				require.NoError(t, err)
				assert.Equal(t, c.approve, users.IsApproved(u), name)
			}
			u, err := userSvc.FindByID(ctx, bare)
			require.NoError(t, err)
			assert.False(t, users.IsApproved(u), "an account that is not in use waits")
		})
	}
}

// The server makes that call at start: a token holder whose account has
// no approval yet can use the server in approval mode right away.
func TestAppApprovesAccountsInUseAtStart(t *testing.T) {
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	holder := dbtest.InsertUser(t, pool, "holder@example.com")
	_, err := pool.Exec(ctx, `INSERT INTO api_tokens (user_id, name, token_hash, token_prefix)
		VALUES ($1, 'laptop', '\x05', 'eeeeeeee')`, holder)
	require.NoError(t, err)

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	cfg := loadConfig(t, fmt.Sprintf(`domain: tunnel.test
listen: {tunnel_addr: "127.0.0.1:0", http_addr: "127.0.0.1:0"}
tls: {self_signed_hosts: [tunnel.test, "*.tunnel.test"]}
auth: {csrf_key: %q, signup: approval}
database: {url: %q}
metrics: {addr: ""}
`, key, os.Getenv("TUNNELD_TEST_DATABASE_URL")))
	logger, logs := captureLog()
	a, err := newApp(ctx, cfg, logger)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = a.closeFrontend(5 * time.Second)
		a.closePool()
	})

	u, err := a.users.FindByID(ctx, holder)
	require.NoError(t, err)
	assert.True(t, users.IsApproved(u), "the token holder is approved at start")
	assert.Contains(t, logs.String(), "signup approval: existing accounts approved")
}

// closingHandler records the context Close is called with.
type closingHandler struct {
	http.Handler
	deadline time.Time
	hadErr   error
}

func (c *closingHandler) Close(ctx context.Context) error {
	c.deadline, _ = ctx.Deadline()
	c.hadErr = ctx.Err()
	return nil
}

// At shutdown the web UI's mail sender gets a deadline of its own, not the
// already ended server context.
func TestCloseFrontendHasItsOwnDeadline(t *testing.T) {
	h := &closingHandler{Handler: http.NotFoundHandler()}
	a := &app{frontend: h}
	before := time.Now()
	require.NoError(t, a.closeFrontend(5*time.Second))
	assert.NoError(t, h.hadErr, "a fresh context")
	assert.WithinDuration(t, before.Add(5*time.Second), h.deadline, time.Second)

	assert.NoError(t, (&app{}).closeFrontend(time.Second), "static-token mode has no web UI")
}

// recordingCloser marks that the web UI was closed.
type recordingCloser struct {
	http.Handler
	closed *atomic.Bool
}

func (r *recordingCloser) Close(ctx context.Context) error {
	r.closed.Store(true)
	if c, ok := r.Handler.(interface{ Close(context.Context) error }); ok {
		return c.Close(ctx)
	}
	return nil
}

// A start that fails after the server was assembled (here: the public port
// is taken) stops the web UI's mail sender and has started no background
// loop, so no ACME renewal began.
func TestRunServerCleansUpWhenABindFails(t *testing.T) {
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	occupied, err := net.Listen("tcp", testports.Loopback+":0")
	require.NoError(t, err)
	defer occupied.Close()

	var closed atomic.Bool
	prev := newFrontend
	newFrontend = func(o frontend.Options) http.Handler {
		return &recordingCloser{Handler: frontend.New(o), closed: &closed}
	}
	t.Cleanup(func() { newFrontend = prev })

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	cfg := loadConfig(t, fmt.Sprintf(`domain: tunnel.test
listen: {tunnel_addr: "127.0.0.1:0", http_addr: %q}
tls: {self_signed_hosts: [tunnel.test, "*.tunnel.test"]}
auth: {csrf_key: %q}
database: {url: %q}
metrics: {addr: ""}
`, occupied.Addr().String(), key, os.Getenv("TUNNELD_TEST_DATABASE_URL")))
	logger, logs := captureLog()
	// Bounded: should the bind ever succeed, the test fails at the deadline
	// instead of serving until the go test timeout.
	runCtx, cancelRun := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelRun()
	err = runServer(runCtx, cfg, logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "http listen")
	assert.True(t, closed.Load(), "the mail sender is stopped on this path too")
	assert.NotContains(t, logs.String(), "session revalidation started", "background loops start after every listener is bound")
	assert.NotContains(t, logs.String(), "reaper started")
}

// loginThroughTheUI logs in at https://app.tunnel.test/login on addr like a
// browser: it fetches the form for the CSRF token and posts it.
func loginThroughTheUI(t *testing.T, addr, email, password string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar:     jar,
		Timeout: waitFor,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := client.Get("https://app.tunnel.test/login")
	require.NoError(t, err)
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)
	const marker = `name="gorilla.csrf.Token" value="`
	i := strings.Index(string(body), marker)
	require.GreaterOrEqual(t, i, 0, "no CSRF token in the login page")
	rest := string(body)[i+len(marker):]
	token := rest[:strings.IndexByte(rest, '"')]

	form := url.Values{"email": {email}, "password": {password}, "gorilla.csrf.Token": {token}}
	req, err := http.NewRequest(http.MethodPost, "https://app.tunnel.test/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://app.tunnel.test")
	req.Header.Set("Referer", "https://app.tunnel.test/login")
	res, err = client.Do(req)
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode, "the login succeeds")
	if loc := res.Header.Get("Location"); !strings.HasSuffix(loc, "/dashboard") {
		t.Fatal(errors.New("login redirected to " + loc))
	}
}
