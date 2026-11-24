package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/client/dialer"
	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

// waitFor bounds waits for something the server is expected to do; they end
// as soon as it happens.
const waitFor = 15 * time.Second

const testStaticToken = "twbl_static_token_0001"

// startAcceptor serves opts on a loopback TLS listener and returns its
// address.
func startAcceptor(t *testing.T, opts acceptor.Options) string {
	t.Helper()
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", testports.Loopback+":0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	acc := acceptor.New(opts)
	go func() {
		defer close(done)
		_ = acc.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String()
}

// tunnelClient is a logged-in tunnel client and a channel that is closed
// when the server ends its session.
type tunnelClient struct {
	sess  *dialer.Session
	ended chan struct{}
}

func dialTunnel(t *testing.T, addr, token string) *tunnelClient {
	t.Helper()
	sess, err := dialer.New(dialer.Options{ServerAddr: addr, Token: token, InsecureSkipVerify: true}).Dial(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	c := &tunnelClient{sess: sess, ended: make(chan struct{})}
	go func() {
		defer close(c.ended)
		for {
			s, err := sess.AcceptStream()
			if err != nil {
				return
			}
			_ = s.Close()
		}
	}()
	return c
}

func (c *tunnelClient) requireEnded(t *testing.T, what string) {
	t.Helper()
	select {
	case <-c.ended:
	case <-time.After(waitFor):
		t.Fatalf("%s: the session is still open", what)
	}
}

func (c *tunnelClient) requireAlive(t *testing.T, what string) {
	t.Helper()
	select {
	case <-c.ended:
		t.Fatalf("%s: the session was closed", what)
	default:
	}
	// The acceptors of these tests have no TCP edge, so this request gets
	// the same answer from a live session every time.
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	_, err := c.sess.RegisterTCP(ctx, 0)
	require.EqualError(t, err, "tcp tunneling disabled", "%s: the session answers", what)
}

// tokenOf issues a token for a new account and returns the raw token, the
// token ID and the account ID.
func tokenOf(t *testing.T, svc *tokens.Service, userID int64) (raw string, tokenID int64) {
	t.Helper()
	raw, row, err := svc.Issue(context.Background(), userID, "laptop")
	require.NoError(t, err)
	return raw, row.ID
}

func TestRevalidationClosesSessionsWhoseTokenIsNoLongerValid(t *testing.T) {
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tokenSvc := tokens.NewService(pool)

	reg := registry.New()
	dbAddr := startAcceptor(t, acceptor.Options{
		Domain: "tunnel.test", Registry: reg, DBVerifier: auth.NewDBVerifier(tokenSvc),
	})
	static, err := auth.NewStaticTokenVerifier([]string{testStaticToken})
	require.NoError(t, err)
	staticAddr := startAcceptor(t, acceptor.Options{Domain: "tunnel.test", Registry: reg, Verifier: static})

	revokedRaw, revokedID := tokenOf(t, tokenSvc, dbtest.InsertUser(t, pool, "revoked@example.com"))
	disabledUser := dbtest.InsertUser(t, pool, "disabled@example.com")
	disabledRaw, _ := tokenOf(t, tokenSvc, disabledUser)
	deletedRaw, deletedID := tokenOf(t, tokenSvc, dbtest.InsertUser(t, pool, "deleted@example.com"))
	validRaw, validID := tokenOf(t, tokenSvc, dbtest.InsertUser(t, pool, "valid@example.com"))

	revoked := dialTunnel(t, dbAddr, revokedRaw)
	disabled := dialTunnel(t, dbAddr, disabledRaw)
	deleted := dialTunnel(t, dbAddr, deletedRaw)
	valid := dialTunnel(t, dbAddr, validRaw)
	staticClient := dialTunnel(t, staticAddr, testStaticToken)

	// The changes happen behind the server's back, as the admin CLI does
	// them: nothing calls the registry.
	for _, q := range []struct {
		sql string
		arg int64
	}{
		{`UPDATE api_tokens SET revoked_at = now() WHERE id = $1`, revokedID},
		{`UPDATE users SET disabled_at = now() WHERE id = $1`, disabledUser},
		{`DELETE FROM api_tokens WHERE id = $1`, deletedID},
	} {
		tag, err := pool.Exec(ctx, q.sql, q.arg)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected(), q.sql)
	}

	logger, logs := captureLog()
	v := newSessionRevalidator(reg, tokenSvc, time.Hour, logger)
	closed, err := v.sweep(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, closed)

	revoked.requireEnded(t, "revoked token")
	disabled.requireEnded(t, "disabled account")
	deleted.requireEnded(t, "deleted token")
	valid.requireAlive(t, "valid token")
	staticClient.requireAlive(t, "static token")
	assert.Equal(t, []int64{validID}, reg.TokenIDs())
	assert.Empty(t, logs.String(), "sweep itself does not log; run does")

	// A failing query closes nothing, even if it named IDs.
	failing := newSessionRevalidator(reg, checkerFunc(func(_ context.Context, ids []int64) ([]int64, error) {
		return ids, errors.New("connection refused")
	}), time.Hour, logger)
	closed, err = failing.sweep(ctx)
	require.Error(t, err)
	assert.Zero(t, closed)
	valid.requireAlive(t, "valid token after a failed sweep")
	staticClient.requireAlive(t, "static token after a failed sweep")

	// So does a real database error.
	pool.Close()
	closed, err = v.sweep(ctx)
	require.Error(t, err)
	assert.Zero(t, closed)
	valid.requireAlive(t, "valid token while the database is gone")
}

// checkerFunc adapts a function to tokenChecker.
type checkerFunc func(ctx context.Context, ids []int64) ([]int64, error)

func (f checkerFunc) InvalidTokenIDs(ctx context.Context, ids []int64) ([]int64, error) {
	return f(ctx, ids)
}

// closableSession is a registry session with a token and a close flag.
type closableSession struct {
	id      string
	tokenID int64
	closed  atomic.Bool
}

func (s *closableSession) ID() string          { return s.id }
func (s *closableSession) UserIDValue() int64  { return 1 }
func (s *closableSession) TokenIDValue() int64 { return s.tokenID }
func (s *closableSession) Close() error        { s.closed.Store(true); return nil }

func TestRevalidationSweepAsksOnceForAllTokens(t *testing.T) {
	reg := registry.New()
	for i, tok := range []int64{4, 4, 8, 0} {
		require.NoError(t, reg.AddSession(&closableSession{id: string(rune('a' + i)), tokenID: tok}, registry.SessionLimits{}))
	}
	var calls [][]int64
	v := newSessionRevalidator(reg, checkerFunc(func(_ context.Context, ids []int64) ([]int64, error) {
		calls = append(calls, ids)
		return []int64{8}, nil
	}), time.Hour, nil)
	closed, err := v.sweep(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, closed)
	assert.Equal(t, [][]int64{{4, 8}}, calls, "one query with the token IDs of the live sessions, static ones left out")

	// Without database sessions nothing is asked.
	empty := newSessionRevalidator(registry.New(), checkerFunc(func(context.Context, []int64) ([]int64, error) {
		t.Fatal("no query without sessions")
		return nil, nil
	}), time.Hour, nil)
	closed, err = empty.sweep(context.Background())
	require.NoError(t, err)
	assert.Zero(t, closed)
}

func TestRevalidationRunsEveryIntervalAndLogsFailuresRateLimited(t *testing.T) {
	reg := registry.New()
	s := &closableSession{id: "s", tokenID: 3}
	require.NoError(t, reg.AddSession(s, registry.SessionLimits{}))

	var mu sync.Mutex
	calls := 0
	fail := true
	checker := checkerFunc(func(context.Context, []int64) ([]int64, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if fail {
			return nil, errors.New("database down")
		}
		return []int64{3}, nil
	})
	logger, logs := captureLog()
	v := newSessionRevalidator(reg, checker, 20*time.Millisecond, logger)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		v.run(ctx)
	}()

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls >= 5
	}, waitFor, 5*time.Millisecond)
	assert.False(t, s.closed.Load(), "failed sweeps close nothing")
	assert.Equal(t, 1, strings.Count(logs.String(), "session revalidation skipped"),
		"repeated failures are logged once per interval of the log limiter")

	mu.Lock()
	fail = false
	mu.Unlock()
	require.Eventually(t, s.closed.Load, waitFor, 5*time.Millisecond)
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "token is no longer valid") }, waitFor, 5*time.Millisecond)

	cancel()
	select {
	case <-done:
	case <-time.After(waitFor):
		t.Fatal("run did not return after the context ended")
	}
}

// captureLog returns a logger that writes into the returned sink.
func captureLog() (*slog.Logger, *lockedLog) {
	l := &lockedLog{}
	return slog.New(slog.NewTextHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug})), l
}

// lockedLog is a goroutine-safe log sink.
type lockedLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
