package tokens_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
)

// Each test function below opens the database once (that costs about half a
// second) and runs its cases as subtests on distinct accounts.

// setDisabled flips users.disabled_at directly, without users.Disable, so
// the tests below see the effect of the query alone.
func setDisabled(t *testing.T, pool *pgxpool.Pool, userID int64, disabled bool) {
	t.Helper()
	q := `UPDATE users SET disabled_at = NULL WHERE id = $1`
	if disabled {
		q = `UPDATE users SET disabled_at = now() WHERE id = $1`
	}
	tag, err := pool.Exec(context.Background(), q, userID)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
}

// expire sets expires_at of a token relative to now. "Now" is the clock of
// the database, the one the queries compare with: the database runs in a
// VM whose clock can be more than a second away from the test's.
func expire(t *testing.T, pool *pgxpool.Pool, tokenID int64, in time.Duration) {
	t.Helper()
	tag, err := pool.Exec(context.Background(),
		`UPDATE api_tokens SET expires_at = now() + make_interval(secs => $2) WHERE id = $1`,
		tokenID, in.Seconds())
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
}

// --- what makes a token valid -----------------------------------------------

func TestVerifyRules(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	svc := tokens.NewService(pool)

	t.Run("token of a disabled user is rejected", func(t *testing.T) {
		uid := dbtest.InsertUser(t, pool, "disabled-tok@example.com")
		other := dbtest.InsertUser(t, pool, "active-tok@example.com")
		raw, _, err := svc.Issue(ctx, uid, "laptop")
		require.NoError(t, err)
		rawOther, _, err := svc.Issue(ctx, other, "laptop")
		require.NoError(t, err)

		got, err := svc.Verify(ctx, raw)
		require.NoError(t, err)
		require.Equal(t, uid, got)

		setDisabled(t, pool, uid, true)

		_, err = svc.Verify(ctx, raw)
		require.ErrorIs(t, err, tokens.ErrInvalidToken, "token of a disabled user must not verify")
		_, _, err = svc.VerifyWithID(ctx, raw)
		require.ErrorIs(t, err, tokens.ErrInvalidToken)

		// Another user's token is unaffected.
		got, err = svc.Verify(ctx, rawOther)
		require.NoError(t, err)
		assert.Equal(t, other, got)

		// Re-enabling the account makes the same token usable again: the
		// token itself was never revoked.
		setDisabled(t, pool, uid, false)
		got, err = svc.Verify(ctx, raw)
		require.NoError(t, err)
		assert.Equal(t, uid, got)
	})

	t.Run("VerifyWithID returns user and token", func(t *testing.T) {
		uid := dbtest.InsertUser(t, pool, "with-id@example.com")
		raw1, row1, err := svc.Issue(ctx, uid, "one")
		require.NoError(t, err)
		raw2, row2, err := svc.Issue(ctx, uid, "two")
		require.NoError(t, err)
		require.NotEqual(t, row1.ID, row2.ID)

		gotUser, gotToken, err := svc.VerifyWithID(ctx, raw1)
		require.NoError(t, err)
		assert.Equal(t, uid, gotUser)
		assert.Equal(t, row1.ID, gotToken)

		gotUser, gotToken, err = svc.VerifyWithID(ctx, raw2)
		require.NoError(t, err)
		assert.Equal(t, uid, gotUser)
		assert.Equal(t, row2.ID, gotToken)

		for _, bad := range []string{"", "twbl_bogus000000000000000000000000000000"} {
			gotUser, gotToken, err = svc.VerifyWithID(ctx, bad)
			require.ErrorIs(t, err, tokens.ErrInvalidToken)
			assert.Zero(t, gotUser)
			assert.Zero(t, gotToken)
		}
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		uid := dbtest.InsertUser(t, pool, "expiry@example.com")
		raw, row, err := svc.Issue(ctx, uid, "expiring")
		require.NoError(t, err)
		assert.False(t, row.ExpiresAt.Valid, "tokens are created without an expiry")

		// An expiry in the future does not get in the way.
		expire(t, pool, row.ID, time.Hour)
		_, err = svc.Verify(ctx, raw)
		require.NoError(t, err)
		n, err := svc.CountActiveByUser(ctx, uid)
		require.NoError(t, err)
		assert.Equal(t, 1, n)

		// Once it has passed, the token is dead for both verify methods.
		expire(t, pool, row.ID, -time.Second)
		_, err = svc.Verify(ctx, raw)
		require.ErrorIs(t, err, tokens.ErrInvalidToken)
		_, _, err = svc.VerifyWithID(ctx, raw)
		require.ErrorIs(t, err, tokens.ErrInvalidToken)

		// Expired tokens do not count as active.
		n, err = svc.CountActiveByUser(ctx, uid)
		require.NoError(t, err)
		assert.Equal(t, 0, n)
		n64, err := svc.CountActiveByUserQuery(ctx, uid)
		require.NoError(t, err)
		assert.EqualValues(t, 0, n64)
	})
}

// --- revocation --------------------------------------------------------------

func TestRevokeRules(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	svc := tokens.NewService(pool)

	t.Run("RevokeForUser is bound to the owner", func(t *testing.T) {
		owner := dbtest.InsertUser(t, pool, "owner@example.com")
		stranger := dbtest.InsertUser(t, pool, "stranger@example.com")
		raw, row, err := svc.Issue(ctx, owner, "laptop")
		require.NoError(t, err)

		// Somebody else names the token id: nothing changes.
		changed, err := svc.RevokeForUser(ctx, stranger, row.ID)
		require.NoError(t, err)
		assert.False(t, changed)
		_, err = svc.Verify(ctx, raw)
		require.NoError(t, err, "token must survive a revoke attempt by another user")

		// The owner revokes it.
		changed, err = svc.RevokeForUser(ctx, owner, row.ID)
		require.NoError(t, err)
		assert.True(t, changed)
		_, err = svc.Verify(ctx, raw)
		require.ErrorIs(t, err, tokens.ErrInvalidToken)

		// A second revoke changes no row and keeps the first timestamp.
		first, err := svc.FindByID(ctx, row.ID)
		require.NoError(t, err)
		require.True(t, first.RevokedAt.Valid)
		changed, err = svc.RevokeForUser(ctx, owner, row.ID)
		require.NoError(t, err)
		assert.False(t, changed)
		changed, err = svc.RevokeAny(ctx, row.ID)
		require.NoError(t, err)
		assert.False(t, changed)
		require.NoError(t, svc.Revoke(ctx, row.ID))
		again, err := svc.FindByID(ctx, row.ID)
		require.NoError(t, err)
		assert.True(t, first.RevokedAt.Time.Equal(again.RevokedAt.Time), "revoked_at must not move")

		// An id that does not exist.
		changed, err = svc.RevokeForUser(ctx, owner, 999999)
		require.NoError(t, err)
		assert.False(t, changed)
	})

	t.Run("RevokeAny ignores the owner", func(t *testing.T) {
		owner := dbtest.InsertUser(t, pool, "admin-revoke@example.com")
		raw, row, err := svc.Issue(ctx, owner, "laptop")
		require.NoError(t, err)
		keepRaw, _, err := svc.Issue(ctx, owner, "desktop")
		require.NoError(t, err)

		changed, err := svc.RevokeAny(ctx, row.ID)
		require.NoError(t, err)
		assert.True(t, changed)
		_, err = svc.Verify(ctx, raw)
		require.ErrorIs(t, err, tokens.ErrInvalidToken)
		_, err = svc.Verify(ctx, keepRaw)
		require.NoError(t, err, "only the named token is revoked")

		changed, err = svc.RevokeAny(ctx, 999999)
		require.NoError(t, err)
		assert.False(t, changed)
	})
}

// --- per-user limits ---------------------------------------------------------

func TestIssueLimits(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	assert.Equal(t, 25, tokens.DefaultMaxActivePerUser)
	assert.Equal(t, 64, tokens.DefaultMaxNameLength)

	t.Run("name length", func(t *testing.T) {
		uid := dbtest.InsertUser(t, pool, "names@example.com")
		svc := tokens.NewService(pool)

		_, row, err := svc.Issue(ctx, uid, strings.Repeat("n", 64))
		require.NoError(t, err)
		assert.Len(t, row.Name, 64)

		// 64 characters that take 128 bytes: the limit counts characters.
		_, _, err = svc.Issue(ctx, uid, strings.Repeat("ü", 64))
		require.NoError(t, err)

		raw, row, err := svc.Issue(ctx, uid, strings.Repeat("n", 65))
		require.ErrorIs(t, err, tokens.ErrNameTooLong)
		assert.Empty(t, raw)
		assert.Nil(t, row)
		_, _, err = svc.Issue(ctx, uid, strings.Repeat("ü", 65))
		require.ErrorIs(t, err, tokens.ErrNameTooLong)
		_, _, err = svc.Issue(ctx, uid, strings.Repeat("n", 1<<20))
		require.ErrorIs(t, err, tokens.ErrNameTooLong)

		n, err := svc.CountActiveByUser(ctx, uid)
		require.NoError(t, err)
		assert.Equal(t, 2, n, "rejected names store nothing")
	})

	t.Run("active tokens per user", func(t *testing.T) {
		uid := dbtest.InsertUser(t, pool, "limit@example.com")
		other := dbtest.InsertUser(t, pool, "limit-other@example.com")
		svc := tokens.NewService(pool) // default: 25

		rows := make([]int64, 0, 25)
		for i := 0; i < 25; i++ {
			_, row, err := svc.Issue(ctx, uid, "t")
			require.NoError(t, err, "token %d", i+1)
			rows = append(rows, row.ID)
		}

		raw, row, err := svc.Issue(ctx, uid, "one too many")
		require.ErrorIs(t, err, tokens.ErrTooManyTokens)
		assert.Empty(t, raw)
		assert.Nil(t, row)
		n, err := svc.CountActiveByUser(ctx, uid)
		require.NoError(t, err)
		assert.Equal(t, 25, n)

		// The limit is per user.
		_, _, err = svc.Issue(ctx, other, "t")
		require.NoError(t, err)

		// A revoked token frees a place...
		changed, err := svc.RevokeForUser(ctx, uid, rows[0])
		require.NoError(t, err)
		require.True(t, changed)
		_, _, err = svc.Issue(ctx, uid, "after revoke")
		require.NoError(t, err)
		_, _, err = svc.Issue(ctx, uid, "full again")
		require.ErrorIs(t, err, tokens.ErrTooManyTokens)

		// ...and so does an expired one.
		expire(t, pool, rows[1], -time.Second)
		_, _, err = svc.Issue(ctx, uid, "after expiry")
		require.NoError(t, err)
		_, _, err = svc.Issue(ctx, uid, "full once more")
		require.ErrorIs(t, err, tokens.ErrTooManyTokens)
	})

	t.Run("the limit holds under concurrent requests", func(t *testing.T) {
		uid := dbtest.InsertUser(t, pool, "limit-race@example.com")
		svc := tokens.NewServiceWithOptions(pool, tokens.Options{MaxActivePerUser: 3})

		const callers = 12
		errs := make([]error, callers)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, _, errs[i] = svc.Issue(ctx, uid, "racer")
			}()
		}
		close(start)
		wg.Wait()

		var issued, refused int
		for _, err := range errs {
			switch {
			case err == nil:
				issued++
			case assert.ErrorIs(t, err, tokens.ErrTooManyTokens):
				refused++
			}
		}
		assert.Equal(t, 3, issued)
		assert.Equal(t, callers-3, refused)
		n, err := svc.CountActiveByUserQuery(ctx, uid)
		require.NoError(t, err)
		assert.EqualValues(t, 3, n, "rows in the table")
	})

	t.Run("options: zero selects the defaults", func(t *testing.T) {
		uid := dbtest.InsertUser(t, pool, "opts-zero@example.com")
		svc := tokens.NewServiceWithOptions(pool, tokens.Options{})
		for i := 0; i < 25; i++ {
			_, _, err := svc.Issue(ctx, uid, "t")
			require.NoError(t, err)
		}
		_, _, err := svc.Issue(ctx, uid, "t")
		require.ErrorIs(t, err, tokens.ErrTooManyTokens)
		_, _, err = svc.Issue(ctx, uid, strings.Repeat("n", 65))
		require.ErrorIs(t, err, tokens.ErrNameTooLong)
	})

	t.Run("options: positive values are used", func(t *testing.T) {
		uid := dbtest.InsertUser(t, pool, "opts-custom@example.com")
		svc := tokens.NewServiceWithOptions(pool, tokens.Options{MaxActivePerUser: 2, MaxNameLength: 5})
		_, _, err := svc.Issue(ctx, uid, "12345")
		require.NoError(t, err)
		_, _, err = svc.Issue(ctx, uid, "123456")
		require.ErrorIs(t, err, tokens.ErrNameTooLong)
		_, _, err = svc.Issue(ctx, uid, "ok")
		require.NoError(t, err)
		_, _, err = svc.Issue(ctx, uid, "full")
		require.ErrorIs(t, err, tokens.ErrTooManyTokens)
	})

	t.Run("options: negative values switch the limits off", func(t *testing.T) {
		uid := dbtest.InsertUser(t, pool, "opts-off@example.com")
		svc := tokens.NewServiceWithOptions(pool, tokens.Options{MaxActivePerUser: -1, MaxNameLength: -1})
		for i := 0; i < 30; i++ {
			_, _, err := svc.Issue(ctx, uid, "t")
			require.NoError(t, err)
		}
		_, _, err := svc.Issue(ctx, uid, strings.Repeat("n", 500))
		require.NoError(t, err)
	})

	t.Run("unknown user", func(t *testing.T) {
		raw, row, err := tokens.NewService(pool).Issue(ctx, 999999, "ghost")
		require.Error(t, err)
		assert.Empty(t, raw)
		assert.Nil(t, row)
	})
}
