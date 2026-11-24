package acceptor

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// scriptedVerifier answers token checks by the number of the call.
type scriptedVerifier struct {
	mu     sync.Mutex
	calls  int
	answer func(ctx context.Context, call int) (userID, tokenID int64, ok bool)
}

func (s *scriptedVerifier) verify(ctx context.Context, _ string) (int64, int64, bool) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	return s.answer(ctx, call)
}

func (s *scriptedVerifier) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// dbModeOpts returns Options for database mode whose token checks the test
// scripts (the verifier itself is never called).
func dbModeOpts(reg *registry.Registry) Options {
	return Options{Registry: reg, DBVerifier: auth.NewDBVerifier(nil), VerifyTimeout: 300 * time.Millisecond}
}

// requireRefusedLogin checks that the login is refused like one with a bad
// token and that nothing of the session is left in the registry.
func requireRefusedLogin(t *testing.T, addr string, reg *registry.Registry) {
	t.Helper()
	c := connect(t, addr)
	ack := c.hello("twbl_some_token")
	assert.Equal(t, "invalid token", ack.Error)
	assert.Empty(t, ack.SessionID)
	c.requireClosed(waitFor)
	require.Eventually(t, func() bool { return len(reg.SnapshotAll()) == 0 }, waitFor, 10*time.Millisecond,
		"the session must not stay in the registry")
}

// A token that is revoked, or an account that is disabled, between the token
// check and the registration of the session must not get a session that
// lives until the next revalidation: the token is checked once more after the
// session is registered, and a refusal tears the session down.
func TestTokenIsCheckedAgainAfterTheSessionIsRegistered(t *testing.T) {
	t.Run("refused the second time", func(t *testing.T) {
		reg := registry.New()
		v := &scriptedVerifier{answer: func(_ context.Context, call int) (int64, int64, bool) {
			return 7, 70, call == 1
		}}
		addr, _ := serve(t, dbModeOpts(reg), func(a *Acceptor) { a.verifyToken = v.verify })
		requireRefusedLogin(t, addr, reg)
		assert.Equal(t, 2, v.count())
	})

	t.Run("the second check fails", func(t *testing.T) {
		reg := registry.New()
		v := &scriptedVerifier{answer: func(ctx context.Context, call int) (int64, int64, bool) {
			if call == 1 {
				return 7, 70, true
			}
			<-ctx.Done() // the database does not answer within the bound
			return 0, 0, false
		}}
		addr, _ := serve(t, dbModeOpts(reg), func(a *Acceptor) { a.verifyToken = v.verify })
		requireRefusedLogin(t, addr, reg)
	})

	t.Run("another user the second time", func(t *testing.T) {
		reg := registry.New()
		v := &scriptedVerifier{answer: func(_ context.Context, call int) (int64, int64, bool) {
			return int64(call), 70, true
		}}
		addr, _ := serve(t, dbModeOpts(reg), func(a *Acceptor) { a.verifyToken = v.verify })
		requireRefusedLogin(t, addr, reg)
	})

	t.Run("accepted twice", func(t *testing.T) {
		reg := registry.New()
		v := &scriptedVerifier{answer: func(context.Context, int) (int64, int64, bool) { return 7, 70, true }}
		addr, _ := serve(t, dbModeOpts(reg), func(a *Acceptor) { a.verifyToken = v.verify })
		c := connect(t, addr)
		ack := c.hello("twbl_some_token")
		require.Empty(t, ack.Error)
		c.requireOpen()
		assert.Len(t, reg.SnapshotAll(), 1)
		assert.Equal(t, 2, v.count(), "one check before and one after the registration")
	})
}

// With a slow database the two token checks could take longer than the
// handshake deadline, which also covers the TLS handshake: the answer would
// meet a connection past its deadline and the client would see it dropped,
// while the session stayed in the registry until the second check returned.
// The second check is bounded by the time left on the handshake deadline,
// with room for the answer: the client gets "invalid token" (fail closed) and
// nothing is left in the registry.
func TestTheSecondCheckEndsInTimeForAnAnswer(t *testing.T) {
	reg := registry.New()
	opts := dbModeOpts(reg)
	opts.HandshakeTimeout = 1500 * time.Millisecond
	opts.VerifyTimeout = 5 * time.Second
	var second atomic.Int64
	v := &scriptedVerifier{answer: func(ctx context.Context, call int) (int64, int64, bool) {
		if call == 1 {
			time.Sleep(900 * time.Millisecond) // a slow database
			return 7, 70, true
		}
		start := time.Now()
		<-ctx.Done() // and one that does not answer at all now
		second.Store(int64(time.Since(start)))
		return 0, 0, false
	}}
	addr, _ := serve(t, opts, func(a *Acceptor) { a.verifyToken = v.verify })
	start := time.Now()
	requireRefusedLogin(t, addr, reg)
	assert.Less(t, time.Since(start), opts.HandshakeTimeout+time.Second)
	assert.Less(t, time.Duration(second.Load()), 600*time.Millisecond, "the second check was not bounded by the handshake deadline")
	assert.Equal(t, 2, v.count())
}

// The same with a real database: the token is revoked right after the first
// check.
func TestTokenRevokedDuringTheLoginEndsTheSession(t *testing.T) {
	fx := newDBFixture(t)
	uid, raw := fx.user(t, "racer@example.com")
	reg := registry.New()
	opts := fx.dbOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, func(a *Acceptor) {
		real := a.verifyToken
		var once sync.Once
		a.verifyToken = func(ctx context.Context, token string) (int64, int64, bool) {
			gotUser, gotToken, ok := real(ctx, token)
			once.Do(func() {
				require.Equal(t, uid, gotUser)
				require.NoError(t, fx.tokens.Revoke(context.Background(), gotToken))
			})
			return gotUser, gotToken, ok
		}
	})
	c := connect(t, addr)
	ack := c.hello(raw)
	assert.Equal(t, "invalid token", ack.Error)
	c.requireClosed(waitFor)
	require.Eventually(t, func() bool { return len(reg.SnapshotAll()) == 0 }, waitFor, 10*time.Millisecond)
}

// In static-token mode there is nothing to check again: the tokens are fixed
// for the life of the process.
func TestStaticModeChecksTheTokenOnce(t *testing.T) {
	addr, acc := serve(t, staticOpts(), nil)
	assert.Nil(t, acc.verifyToken)
	login(t, addr, staticToken)
}
