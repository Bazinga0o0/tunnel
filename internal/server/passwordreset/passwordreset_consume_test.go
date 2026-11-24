package passwordreset

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func countRows(t *testing.T, pool *pgxpool.Pool, table string, userID int64) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM `+table+` WHERE user_id = $1`, userID).Scan(&n))
	return n
}

// --- the stored address ------------------------------------------------------

func TestIssueWithAddressReturnsTheStoredAddress(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	svc := NewService(pool, userSvc, sessions.NewService(pool))
	u, err := userSvc.Create(ctx, "Stored.Spelling@Example.com", "oldpw1234")
	require.NoError(t, err)

	// The client types a different spelling of the same (case-insensitive)
	// address. The address to mail is the one in the database.
	raw, userID, stored, err := svc.IssueWithAddress(ctx, "stored.spelling@EXAMPLE.COM")
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	assert.Equal(t, u.ID, userID)
	assert.Equal(t, "Stored.Spelling@Example.com", stored)

	// The token it returned is a working reset token.
	gotUID, err := svc.Consume(ctx, raw, "newpw5678")
	require.NoError(t, err)
	assert.Equal(t, u.ID, gotUID)

	// Unknown address: no token, no address, no error (no enumeration).
	raw, userID, stored, err = svc.IssueWithAddress(ctx, "nobody@example.com")
	require.NoError(t, err)
	assert.Empty(t, raw)
	assert.Zero(t, userID)
	assert.Empty(t, stored)

	// Issue keeps its old shape and agrees with IssueWithAddress.
	raw, userID, err = svc.Issue(ctx, "STORED.SPELLING@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, raw)
	assert.Equal(t, u.ID, userID)
}

// --- hash work only for a live token ------------------------------------------

func TestConsumeHashesOnlyForALiveToken(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	svc := NewService(pool, userSvc, sessions.NewService(pool))
	u, err := userSvc.Create(ctx, "hash-cost@example.com", "oldpw1234")
	require.NoError(t, err)

	var hashes int
	var busy error
	realHash := svc.hash
	svc.hash = func(ctx context.Context, password string) (string, error) {
		hashes++
		if busy != nil {
			return "", busy
		}
		return realHash(ctx, password)
	}

	// Anybody can post a made-up token. That must not cost a password hash.
	for _, raw := range []string{"made-up-token", "", "another-made-up-token"} {
		_, err := svc.Consume(ctx, raw, "newpw5678")
		require.ErrorIs(t, err, ErrInvalidReset, "%q", raw)
	}
	assert.Equal(t, 0, hashes, "no hash for a token that does not exist")

	raw, _, err := svc.Issue(ctx, "hash-cost@example.com")
	require.NoError(t, err)

	// No hashing slot: the caller learns that, and the token stays usable.
	busy = auth.ErrBusy
	_, err = svc.Consume(ctx, raw, "newpw5678")
	require.ErrorIs(t, err, auth.ErrBusy)
	assert.NotErrorIs(t, err, ErrInvalidReset)
	assert.Equal(t, 1, countRows(t, pool, "password_resets", u.ID), "a busy hash does not use the token up")
	busy = nil
	hashes = 0

	_, err = svc.Consume(ctx, raw, "newpw5678")
	require.NoError(t, err)
	assert.Equal(t, 1, hashes, "one hash for the one password change")

	// The used token is as good as a made-up one.
	_, err = svc.Consume(ctx, raw, "newpw5678")
	require.ErrorIs(t, err, ErrInvalidReset)
	assert.Equal(t, 1, hashes, "no hash for a used token")

	// A token that runs out while the password is being hashed is refused:
	// the look before the hash decides nothing.
	raw, _, err = svc.Issue(ctx, "hash-cost@example.com")
	require.NoError(t, err)
	svc.hash = func(ctx context.Context, password string) (string, error) {
		_, err := pool.Exec(ctx, `UPDATE password_resets SET expires_at = now() - interval '1 second' WHERE user_id = $1`, u.ID)
		require.NoError(t, err)
		return realHash(ctx, password)
	}
	_, err = svc.Consume(ctx, raw, "too-late-pw-1")
	require.ErrorIs(t, err, ErrInvalidReset)
	ok, err := userSvc.VerifyPassword(ctx, u.ID, "too-late-pw-1")
	require.NoError(t, err)
	assert.False(t, ok, "the password of an expired link is not set")
}

// --- concurrent and transactional consume -------------------------------------

func TestConsumeUnderTwoConcurrentCallsSucceedsOnce(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	sessSvc := sessions.NewService(pool)
	svc := NewService(pool, userSvc, sessSvc)
	u, err := userSvc.Create(ctx, "race@example.com", "oldpw1234")
	require.NoError(t, err)

	for round := 0; round < 3; round++ {
		raw, _, err := svc.Issue(ctx, "race@example.com")
		require.NoError(t, err)

		passwords := []string{"winner-pw-one", "winner-pw-two"}
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range passwords {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[i] = svc.Consume(ctx, raw, passwords[i])
			}()
		}
		close(start)
		wg.Wait()

		var winner string
		var succeeded, refused int
		for i, err := range errs {
			switch {
			case err == nil:
				succeeded++
				winner = passwords[i]
			case assert.ErrorIs(t, err, ErrInvalidReset, "round %d", round):
				refused++
			}
		}
		require.Equal(t, 1, succeeded, "round %d: one token must change the password once (errors: %v)", round, errs)
		require.Equal(t, 1, refused, "round %d", round)

		// The stored password is the one from the call that succeeded.
		for _, pw := range passwords {
			ok, err := userSvc.VerifyPassword(ctx, u.ID, pw)
			require.NoError(t, err)
			assert.Equal(t, pw == winner, ok, "round %d: password %q", round, pw)
		}
		assert.Equal(t, 0, countRows(t, pool, "password_resets", u.ID), "round %d", round)
	}
}

func TestConsumeIsOneTransaction(t *testing.T) {
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	userSvc := users.NewService(pool)
	sessSvc := sessions.NewService(pool)
	svc := NewService(pool, userSvc, sessSvc)

	t.Run("success deletes sessions and every other reset of the account only", func(t *testing.T) {
		u, err := userSvc.Create(ctx, "cleanup@example.com", "oldpw1234")
		require.NoError(t, err)
		other := dbtest.InsertUser(t, pool, "cleanup-other@example.com")

		rawSession, _, err := sessSvc.Create(ctx, u.ID, "", netip.Addr{}, time.Hour)
		require.NoError(t, err)
		otherSession, _, err := sessSvc.Create(ctx, other, "", netip.Addr{}, time.Hour)
		require.NoError(t, err)

		first, _, err := svc.Issue(ctx, "cleanup@example.com")
		require.NoError(t, err)
		second, _, err := svc.Issue(ctx, "cleanup@example.com")
		require.NoError(t, err)
		otherReset, _, err := svc.Issue(ctx, "cleanup-other@example.com")
		require.NoError(t, err)

		uid, err := svc.Consume(ctx, first, "newpw5678")
		require.NoError(t, err)
		assert.Equal(t, u.ID, uid)

		_, err = sessSvc.Lookup(ctx, rawSession)
		require.ErrorIs(t, err, sessions.ErrInvalidSession, "sessions of the account are gone")
		_, err = svc.Consume(ctx, second, "anotherpw99")
		require.ErrorIs(t, err, ErrInvalidReset, "the second open link is dead")
		ok, err := userSvc.VerifyPassword(ctx, u.ID, "newpw5678")
		require.NoError(t, err)
		assert.True(t, ok)

		// The other account keeps its session and its reset link.
		_, err = sessSvc.Lookup(ctx, otherSession)
		require.NoError(t, err)
		_, err = svc.Consume(ctx, otherReset, "othernewpw1")
		require.NoError(t, err)
	})

	t.Run("a failing step rolls everything back", func(t *testing.T) {
		u, err := userSvc.Create(ctx, "rollback@example.com", "oldpw1234")
		require.NoError(t, err)
		rawSession, _, err := sessSvc.Create(ctx, u.ID, "", netip.Addr{}, time.Hour)
		require.NoError(t, err)
		raw, _, err := svc.Issue(ctx, "rollback@example.com")
		require.NoError(t, err)

		// Deleting the sessions comes after the token is taken and the
		// password is set. When it fails, neither may stick.
		undo := dbtest.FailDeletes(t, pool, "sessions")
		defer undo()

		_, err = svc.Consume(ctx, raw, "newpw5678")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrInvalidReset, "an internal failure is not an invalid token")

		ok, err := userSvc.VerifyPassword(ctx, u.ID, "oldpw1234")
		require.NoError(t, err)
		assert.True(t, ok, "old password still valid")
		ok, err = userSvc.VerifyPassword(ctx, u.ID, "newpw5678")
		require.NoError(t, err)
		assert.False(t, ok, "new password was rolled back")
		_, err = sessSvc.Lookup(ctx, rawSession)
		require.NoError(t, err, "session still there")
		assert.Equal(t, 1, countRows(t, pool, "password_resets", u.ID), "token still there")

		// With the failure gone the very same token works: it was not used up.
		undo()
		_, err = svc.Consume(ctx, raw, "newpw5678")
		require.NoError(t, err)
		ok, err = userSvc.VerifyPassword(ctx, u.ID, "newpw5678")
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("an expired token is rejected", func(t *testing.T) {
		u, err := userSvc.Create(ctx, "expired@example.com", "oldpw1234")
		require.NoError(t, err)

		const raw = "expired-raw-token"
		sum := sha256.Sum256([]byte(raw))
		require.NoError(t, sqlcgen.New(pool).CreatePasswordReset(ctx, sqlcgen.CreatePasswordResetParams{
			TokenHash:  sum[:],
			UserID:     u.ID,
			TtlSeconds: -60, // a minute before the database's now
		}))

		_, err = svc.Consume(ctx, raw, "newpw5678")
		require.ErrorIs(t, err, ErrInvalidReset)
		ok, err := userSvc.VerifyPassword(ctx, u.ID, "oldpw1234")
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("a rejected password does not use the token up", func(t *testing.T) {
		u, err := userSvc.Create(ctx, "runes@example.com", "oldpw1234")
		require.NoError(t, err)
		raw, _, err := svc.Issue(ctx, "runes@example.com")
		require.NoError(t, err)

		// Seven characters in fourteen bytes.
		_, err = svc.Consume(ctx, raw, "äääääää")
		require.ErrorIs(t, err, users.ErrPasswordTooShort)
		_, err = svc.Consume(ctx, raw, string(make([]byte, users.MaxPasswordBytes+1)))
		require.ErrorIs(t, err, users.ErrPasswordTooLong)
		assert.Equal(t, 1, countRows(t, pool, "password_resets", u.ID))

		_, err = svc.Consume(ctx, raw, "ääääääää")
		require.NoError(t, err)
	})
}
