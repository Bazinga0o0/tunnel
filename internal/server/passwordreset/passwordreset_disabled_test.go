package passwordreset

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// setDisabled flips users.disabled_at directly. users.Disable would also
// delete the open reset tokens, and these tests need a token to exist.
func setDisabled(t *testing.T, pool *pgxpool.Pool, userID int64, disabled bool) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`UPDATE users SET disabled_at = CASE WHEN $2 THEN now() ELSE NULL END WHERE id = $1`, userID, disabled)
	require.NoError(t, err)
}

func TestResetIsRefusedForADisabledAccount(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	svc := NewService(pool, userSvc, sessions.NewService(pool))
	u, err := userSvc.Create(ctx, "Disabled.Reset@Example.com", "oldpw1234")
	require.NoError(t, err)

	// A link from the time the account was enabled.
	raw, _, _, err := svc.IssueWithAddress(ctx, "disabled.reset@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	setDisabled(t, pool, u.ID, true)

	oldPasswordStillValid := func(msg string) {
		t.Helper()
		ok, err := userSvc.VerifyPassword(ctx, u.ID, "oldpw1234")
		require.NoError(t, err)
		assert.True(t, ok, msg)
	}

	t.Run("a new link is refused exactly like one for an unknown address", func(t *testing.T) {
		unknownRaw, unknownID, unknownEmail, unknownErr := svc.IssueWithAddress(ctx, "nobody@example.com")

		gotRaw, gotID, gotEmail, gotErr := svc.IssueWithAddress(ctx, "disabled.reset@example.com")
		assert.Equal(t, unknownErr, gotErr)
		require.NoError(t, gotErr)
		assert.Equal(t, unknownRaw, gotRaw)
		assert.Equal(t, unknownID, gotID)
		assert.Equal(t, unknownEmail, gotEmail)
		assert.Empty(t, gotRaw, "no token for a disabled account")
		assert.Empty(t, gotEmail, "no address to mail for a disabled account")

		legacyRaw, legacyID, err := svc.Issue(ctx, "disabled.reset@example.com")
		require.NoError(t, err)
		assert.Empty(t, legacyRaw)
		assert.Zero(t, legacyID)

		assert.Equal(t, 1, countRows(t, pool, "password_resets", u.ID), "no token row was written")
	})

	t.Run("an existing link does not change the password and costs no hash", func(t *testing.T) {
		var hashes int
		realHash := svc.hash
		svc.hash = func(ctx context.Context, password string) (string, error) {
			hashes++
			return realHash(ctx, password)
		}
		defer func() { svc.hash = realHash }()

		_, err := svc.Consume(ctx, raw, "newpw5678")
		require.ErrorIs(t, err, ErrInvalidReset)
		assert.Equal(t, 0, hashes)
		oldPasswordStillValid("the password of a disabled account stays")
	})

	t.Run("an account disabled while the password is hashed keeps its password", func(t *testing.T) {
		setDisabled(t, pool, u.ID, false)
		realHash := svc.hash
		svc.hash = func(ctx context.Context, password string) (string, error) {
			setDisabled(t, pool, u.ID, true)
			return realHash(ctx, password)
		}
		defer func() { svc.hash = realHash }()

		_, err := svc.Consume(ctx, raw, "newpw5678")
		require.ErrorIs(t, err, ErrInvalidReset)
		oldPasswordStillValid("the look before the hash decides nothing")
	})

	t.Run("after the account is enabled again a link works", func(t *testing.T) {
		setDisabled(t, pool, u.ID, false)
		fresh, _, stored, err := svc.IssueWithAddress(ctx, "disabled.reset@example.com")
		require.NoError(t, err)
		require.NotEmpty(t, fresh)
		assert.Equal(t, "Disabled.Reset@Example.com", stored)
		_, err = svc.Consume(ctx, fresh, "newpw5678")
		require.NoError(t, err)
	})
}

func TestConsumeDoesNotDeadlockWithAnotherChangeToTheAccount(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	svc := NewService(pool, userSvc, sessions.NewService(pool))
	u, err := userSvc.Create(ctx, "lock-order@example.com", "oldpw1234")
	require.NoError(t, err)
	raw, _, _, err := svc.IssueWithAddress(ctx, "lock-order@example.com")
	require.NoError(t, err)

	// Another transaction holds the account row, as users.Disable and the
	// password changes in users do before they delete the reset tokens.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, u.ID)
	require.NoError(t, err)

	hashed := make(chan struct{})
	realHash := svc.hash
	svc.hash = func(ctx context.Context, password string) (string, error) {
		defer close(hashed)
		return realHash(ctx, password)
	}
	done := make(chan error, 1)
	go func() {
		_, err := svc.Consume(ctx, raw, "newpw5678")
		done <- err
	}()

	// Consume is past the hash and inside its transaction, waiting.
	<-hashed
	select {
	case err := <-done:
		t.Fatalf("Consume did not wait for the lock on the account row (returned %v)", err)
	case <-time.After(500 * time.Millisecond):
	}

	// The other transaction goes on to the reset tokens. Had Consume taken
	// the token row before it asked for the account row, the two would now
	// wait for each other and the database would end one of them.
	_, err = tx.Exec(ctx, `DELETE FROM password_resets WHERE user_id = $1`, u.ID)
	require.NoError(t, err, "the other transaction must not be the victim of a deadlock")
	require.NoError(t, tx.Commit(ctx))

	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrInvalidReset, "the token was gone when Consume got its turn")
	case <-time.After(15 * time.Second):
		t.Fatal("Consume did not return")
	}
	ok, err := userSvc.VerifyPassword(ctx, u.ID, "oldpw1234")
	require.NoError(t, err)
	assert.True(t, ok)
}
