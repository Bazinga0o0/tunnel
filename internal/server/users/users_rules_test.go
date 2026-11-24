package users

import (
	"context"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
)

// Each test function below opens the database once (that costs about half a
// second) and runs its cases as subtests on distinct accounts.

// --- helpers ---------------------------------------------------------------

// addSession stores a live session row for userID.
func addSession(t *testing.T, pool *pgxpool.Pool, userID int64, label string) {
	t.Helper()
	id := sha256.Sum256([]byte("session-" + label))
	_, err := sqlcgen.New(pool).CreateSession(context.Background(), sqlcgen.CreateSessionParams{
		ID:         id[:],
		UserID:     userID,
		TtlSeconds: 3600,
	})
	require.NoError(t, err)
}

// addReset stores an open password-reset row for userID.
func addReset(t *testing.T, pool *pgxpool.Pool, userID int64, label string) {
	t.Helper()
	h := sha256.Sum256([]byte("reset-" + label))
	require.NoError(t, sqlcgen.New(pool).CreatePasswordReset(context.Background(), sqlcgen.CreatePasswordResetParams{
		TokenHash:  h[:],
		UserID:     userID,
		TtlSeconds: 3600,
	}))
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string, userID int64) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM `+table+` WHERE user_id = $1`, userID).Scan(&n))
	return n
}

// setFlags sets is_admin and disabled_at directly.
func setFlags(t *testing.T, pool *pgxpool.Pool, userID int64, admin, disabled bool) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`UPDATE users SET is_admin = $2, disabled_at = CASE WHEN $3 THEN now() ELSE NULL END WHERE id = $1`,
		userID, admin, disabled)
	require.NoError(t, err)
}

// noAdmins takes the admin flag from every account, so that a subtest
// starts from a known set of admins.
func noAdmins(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `UPDATE users SET is_admin = false WHERE is_admin`)
	require.NoError(t, err)
}

func activeAdmins(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM users WHERE is_admin AND disabled_at IS NULL`).Scan(&n))
	return n
}

// together runs the functions at the same moment and returns their errors
// in order.
func together(fns ...func() error) []error {
	start := make(chan struct{})
	errs := make([]error, len(fns))
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fn()
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

// --- disabled accounts -----------------------------------------------------

func TestDisable(t *testing.T) {
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	svc := NewService(pool)

	t.Run("a disabled admin fails the admin check", func(t *testing.T) {
		id := dbtest.InsertUser(t, pool, "isadmin@example.com")
		setFlags(t, pool, id, true, false)
		ok, err := svc.IsAdmin(ctx, id)
		require.NoError(t, err)
		require.True(t, ok)

		setFlags(t, pool, id, true, true)
		ok, err = svc.IsAdmin(ctx, id)
		require.NoError(t, err)
		assert.False(t, ok)
		noAdmins(t, pool)
	})

	t.Run("deletes sessions and open resets of the account only", func(t *testing.T) {
		target := dbtest.InsertUser(t, pool, "target@example.com")
		bystander := dbtest.InsertUser(t, pool, "bystander@example.com")
		addSession(t, pool, target, "t1")
		addSession(t, pool, target, "t2")
		addReset(t, pool, target, "t1")
		addSession(t, pool, bystander, "b1")
		addReset(t, pool, bystander, "b1")

		// nil purger: the service itself has to remove the sessions.
		require.NoError(t, svc.Disable(ctx, nil, target))

		got, err := svc.FindByID(ctx, target)
		require.NoError(t, err)
		assert.True(t, got.DisabledAt.Valid)
		assert.Equal(t, 0, countRows(t, pool, "sessions", target), "sessions of the disabled user")
		assert.Equal(t, 0, countRows(t, pool, "password_resets", target), "open resets of the disabled user")

		assert.Equal(t, 1, countRows(t, pool, "sessions", bystander), "another user's session is untouched")
		assert.Equal(t, 1, countRows(t, pool, "password_resets", bystander), "another user's reset is untouched")
	})

	t.Run("unknown user", func(t *testing.T) {
		require.ErrorIs(t, svc.Disable(ctx, nil, 999999), ErrNotFound)
	})

	t.Run("is one transaction", func(t *testing.T) {
		target := dbtest.InsertUser(t, pool, "tx-target@example.com")
		addSession(t, pool, target, "tx1")
		addReset(t, pool, target, "tx1")

		// The last step of Disable (deleting the open resets) fails.
		// Everything before it has to be undone: the account stays enabled
		// and keeps its session.
		undo := dbtest.FailDeletes(t, pool, "password_resets")
		defer undo()

		err := svc.Disable(ctx, nil, target)
		require.Error(t, err)

		got, err := svc.FindByID(ctx, target)
		require.NoError(t, err)
		assert.False(t, got.DisabledAt.Valid, "disable must be rolled back")
		assert.Equal(t, 1, countRows(t, pool, "sessions", target), "session delete must be rolled back")
		assert.Equal(t, 1, countRows(t, pool, "password_resets", target))
	})
}

// --- admin rules -----------------------------------------------------------

func TestAdminRules(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	svc := NewService(pool)

	t.Run("disable refuses the last active admin", func(t *testing.T) {
		noAdmins(t, pool)
		admin := dbtest.InsertUser(t, pool, "only-admin@example.com")
		setFlags(t, pool, admin, true, false)
		disabledAdmin := dbtest.InsertUser(t, pool, "disabled-admin@example.com")
		setFlags(t, pool, disabledAdmin, true, true)
		user := dbtest.InsertUser(t, pool, "plain@example.com")
		addSession(t, pool, admin, "a1")

		// One active admin plus one disabled admin: the disabled one does
		// not count, so the active one may not be disabled.
		err := svc.Disable(ctx, nil, admin)
		require.ErrorIs(t, err, ErrLastAdmin)
		got, err := svc.FindByID(ctx, admin)
		require.NoError(t, err)
		assert.False(t, got.DisabledAt.Valid)
		assert.Equal(t, 1, countRows(t, pool, "sessions", admin), "refused disable leaves the sessions alone")

		// A plain user can always be disabled.
		require.NoError(t, svc.Disable(ctx, nil, user))

		// With a second active admin the first can be disabled...
		second := dbtest.InsertUser(t, pool, "second-admin@example.com")
		setFlags(t, pool, second, true, false)
		require.NoError(t, svc.Disable(ctx, nil, admin))
		assert.Equal(t, 1, activeAdmins(t, pool))

		// ...and then the second is the last one.
		require.ErrorIs(t, svc.Disable(ctx, nil, second), ErrLastAdmin)
		assert.Equal(t, 1, activeAdmins(t, pool))

		// Disabling an admin that is already disabled takes nobody away.
		require.NoError(t, svc.Disable(ctx, nil, admin))
	})

	t.Run("without any active admin, a disabled admin can still be demoted and disabled again", func(t *testing.T) {
		// The check protects the last active admin. A disabled admin is not
		// one, whatever else exists, so neither change may be refused.
		noAdmins(t, pool)
		first := dbtest.InsertUser(t, pool, "lone-disabled-1@example.com")
		second := dbtest.InsertUser(t, pool, "lone-disabled-2@example.com")
		setFlags(t, pool, first, true, true)
		setFlags(t, pool, second, true, true)
		require.Equal(t, 0, activeAdmins(t, pool))

		require.NoError(t, svc.Disable(ctx, nil, first), "disable an already disabled admin")
		u, err := svc.FindByID(ctx, first)
		require.NoError(t, err)
		assert.True(t, u.IsAdmin)
		assert.True(t, u.DisabledAt.Valid)

		require.NoError(t, svc.Demote(ctx, second), "demote a disabled admin")
		u, err = svc.FindByID(ctx, second)
		require.NoError(t, err)
		assert.False(t, u.IsAdmin)
	})

	t.Run("demote", func(t *testing.T) {
		noAdmins(t, pool)
		active := dbtest.InsertUser(t, pool, "d-active-admin@example.com")
		setFlags(t, pool, active, true, false)
		disabled := dbtest.InsertUser(t, pool, "d-disabled-admin@example.com")
		setFlags(t, pool, disabled, true, true)
		plain := dbtest.InsertUser(t, pool, "d-plain@example.com")

		// The last active admin stays; a disabled admin does not rescue the check.
		require.ErrorIs(t, svc.Demote(ctx, active), ErrLastAdmin)
		u, err := svc.FindByID(ctx, active)
		require.NoError(t, err)
		assert.True(t, u.IsAdmin)

		// A disabled admin can always be demoted, even next to a single active one.
		require.NoError(t, svc.Demote(ctx, disabled))
		u, err = svc.FindByID(ctx, disabled)
		require.NoError(t, err)
		assert.False(t, u.IsAdmin)
		assert.True(t, u.DisabledAt.Valid, "demotion does not touch disabled_at")

		// Demoting somebody who is no admin changes nothing and is no error.
		require.NoError(t, svc.Demote(ctx, plain))

		// Unknown id.
		require.ErrorIs(t, svc.Demote(ctx, 999999), ErrNotFound)

		// With a second active admin, the first can go.
		second := dbtest.InsertUser(t, pool, "d-second-admin@example.com")
		setFlags(t, pool, second, true, false)
		require.NoError(t, svc.Demote(ctx, active))
		require.ErrorIs(t, svc.Demote(ctx, second), ErrLastAdmin)
		assert.Equal(t, 1, activeAdmins(t, pool))
	})

	// The next two cases leave a change by another connection uncommitted,
	// start the service call and then commit. The call has to wait for the
	// change and decide on what was committed, not on what it saw before.
	t.Run("a demotion waits for a change to the admins that is under way", func(t *testing.T) {
		noAdmins(t, pool)
		a := dbtest.InsertUser(t, pool, "wait-a@example.com")
		b := dbtest.InsertUser(t, pool, "wait-b@example.com")
		setFlags(t, pool, a, true, false)
		setFlags(t, pool, b, true, false)

		// Somebody takes the admin flag from b and has not committed yet.
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, `UPDATE users SET is_admin = false WHERE id = $1`, b)
		require.NoError(t, err)

		done := make(chan error, 1)
		go func() { done <- svc.Demote(ctx, a) }()
		select {
		case err := <-done:
			t.Fatalf("Demote did not wait for the open change (returned %v)", err)
		case <-time.After(300 * time.Millisecond):
		}
		require.NoError(t, tx.Commit(ctx))

		select {
		case err := <-done:
			require.ErrorIs(t, err, ErrLastAdmin, "b is no admin any more, so a is the last one")
		case <-time.After(10 * time.Second):
			t.Fatal("Demote did not return after the commit")
		}
		assert.Equal(t, 1, activeAdmins(t, pool))
	})

	t.Run("a disable waits for a promotion of its target that is under way", func(t *testing.T) {
		noAdmins(t, pool)
		x := dbtest.InsertUser(t, pool, "wait-x@example.com")

		// Somebody promotes x and has not committed yet. Once that is
		// committed, x is the only admin.
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, `UPDATE users SET is_admin = true WHERE id = $1`, x)
		require.NoError(t, err)

		done := make(chan error, 1)
		go func() { done <- svc.Disable(ctx, nil, x) }()
		select {
		case err := <-done:
			t.Fatalf("Disable did not wait for the open change (returned %v)", err)
		case <-time.After(300 * time.Millisecond):
		}
		require.NoError(t, tx.Commit(ctx))

		select {
		case err := <-done:
			require.ErrorIs(t, err, ErrLastAdmin, "x is the only admin now")
		case <-time.After(10 * time.Second):
			t.Fatal("Disable did not return after the commit")
		}
		assert.Equal(t, 1, activeAdmins(t, pool), "x is still active")
	})

	// The last two cases run the same pair of changes at the same moment,
	// 25 times each. Without a lock both changes could read "two admins" and
	// both go through.
	t.Run("two demotions at once keep one admin", func(t *testing.T) {
		noAdmins(t, pool)
		a := dbtest.InsertUser(t, pool, "race-a@example.com")
		b := dbtest.InsertUser(t, pool, "race-b@example.com")

		for round := 0; round < 25; round++ {
			setFlags(t, pool, a, true, false)
			setFlags(t, pool, b, true, false)

			errs := together(
				func() error { return svc.Demote(ctx, a) },
				func() error { return svc.Demote(ctx, b) },
			)

			require.Equal(t, 1, activeAdmins(t, pool), "round %d: exactly one admin must remain (errors: %v)", round, errs)
			var refused, done int
			for _, err := range errs {
				switch {
				case err == nil:
					done++
				case assert.ErrorIs(t, err, ErrLastAdmin):
					refused++
				}
			}
			require.Equal(t, 1, done, "round %d", round)
			require.Equal(t, 1, refused, "round %d", round)
		}
	})

	t.Run("demotion and disable at once keep one admin", func(t *testing.T) {
		noAdmins(t, pool)
		a := dbtest.InsertUser(t, pool, "race-demote@example.com")
		b := dbtest.InsertUser(t, pool, "race-disable@example.com")

		for round := 0; round < 25; round++ {
			setFlags(t, pool, a, true, false)
			setFlags(t, pool, b, true, false)

			errs := together(
				func() error { return svc.Demote(ctx, a) },
				func() error { return svc.Disable(ctx, nil, b) },
			)

			require.Equal(t, 1, activeAdmins(t, pool), "round %d: exactly one active admin must remain (errors: %v)", round, errs)
			var refused int
			for _, err := range errs {
				if err != nil {
					require.ErrorIs(t, err, ErrLastAdmin, "round %d", round)
					refused++
				}
			}
			require.Equal(t, 1, refused, "round %d", round)
		}
	})
}

// --- passwords -------------------------------------------------------------

func TestPasswordRules(t *testing.T) {
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	svc := NewService(pool)

	t.Run("create counts characters, not bytes", func(t *testing.T) {
		// Four umlauts are eight bytes but four characters.
		_, err := svc.Create(ctx, "runes-short@example.com", "ääää")
		require.ErrorIs(t, err, ErrPasswordTooShort)
		_, err = svc.FindByEmail(ctx, "runes-short@example.com")
		require.ErrorIs(t, err, ErrNotFound, "no account for a rejected password")

		// Seven characters, fourteen bytes.
		_, err = svc.Create(ctx, "runes-seven@example.com", "äääääää")
		require.ErrorIs(t, err, ErrPasswordTooShort)

		// Eight characters.
		u, err := svc.Create(ctx, "runes-ok@example.com", "ääääääää")
		require.NoError(t, err)
		ok, err := svc.VerifyPassword(ctx, u.ID, "ääääääää")
		require.NoError(t, err)
		assert.True(t, ok)
	})

	// account creates a user with the password "initialpw1" and returns its
	// id and a check that this is still the password.
	account := func(t *testing.T, email string) (int64, func(string)) {
		t.Helper()
		u, err := svc.Create(ctx, email, "initialpw1")
		require.NoError(t, err)
		return u.ID, func(msg string) {
			t.Helper()
			ok, err := svc.VerifyPassword(ctx, u.ID, "initialpw1")
			require.NoError(t, err)
			assert.True(t, ok, msg)
		}
	}

	t.Run("a change counts characters and reports an unknown user", func(t *testing.T) {
		id, stillInitial := account(t, "pw-update@example.com")
		require.ErrorIs(t, svc.ChangePassword(ctx, id, "äääääää"), ErrPasswordTooShort)
		stillInitial("rejected password must not be stored")
		require.ErrorIs(t, svc.ChangePassword(ctx, 999999, "long enough pw"), ErrNotFound)
	})

	t.Run("a password set by an admin needs twelve characters", func(t *testing.T) {
		id, stillInitial := account(t, "pw-admin-set@example.com")
		// Eleven characters: enough for a user-chosen password, not for one
		// an admin sets.
		err := svc.SetPassword(ctx, id, "elevenchars")
		require.ErrorIs(t, err, ErrPasswordTooShort)
		assert.Contains(t, err.Error(), "at least 12 characters")
		// Twelve bytes, six characters.
		require.ErrorIs(t, svc.SetPassword(ctx, id, "ääääää"), ErrPasswordTooShort)
		stillInitial("rejected password must not be stored")
		require.ErrorIs(t, svc.SetPassword(ctx, 999999, "twelve chars"), ErrNotFound)

		require.NoError(t, svc.SetPassword(ctx, id, "twelve chars"))
		ok, err := svc.VerifyPassword(ctx, id, "twelve chars")
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("a password change deletes the open resets", func(t *testing.T) {
		id, _ := account(t, "pw-change@example.com")
		bystander := dbtest.InsertUser(t, pool, "pw-bystander@example.com")
		addReset(t, pool, bystander, "b")

		addReset(t, pool, id, "one")
		addReset(t, pool, id, "two")
		require.NoError(t, svc.ChangePassword(ctx, id, "second-pw-1"))
		assert.Equal(t, 0, countRows(t, pool, "password_resets", id), "after ChangePassword")

		addReset(t, pool, id, "three")
		require.NoError(t, svc.SetPassword(ctx, id, "third-password-1"))
		assert.Equal(t, 0, countRows(t, pool, "password_resets", id), "after SetPassword")

		assert.Equal(t, 1, countRows(t, pool, "password_resets", bystander), "another user's reset is untouched")
	})

	t.Run("every password change logs the account out", func(t *testing.T) {
		id, _ := account(t, "pw-logout@example.com")
		bystander := dbtest.InsertUser(t, pool, "pw-logout-bystander@example.com")
		addSession(t, pool, id, "logout-1")
		addSession(t, pool, id, "logout-2")
		addSession(t, pool, bystander, "logout-b")

		require.NoError(t, svc.ChangePassword(ctx, id, "second-pw-1"))
		assert.Equal(t, 0, countRows(t, pool, "sessions", id), "after ChangePassword")

		addSession(t, pool, id, "logout-3")
		require.NoError(t, svc.SetPassword(ctx, id, "third-password-1"))
		assert.Equal(t, 0, countRows(t, pool, "sessions", id), "after SetPassword")
		assert.Equal(t, 1, countRows(t, pool, "sessions", bystander), "another user's session is untouched")
	})

	t.Run("a password change is one transaction", func(t *testing.T) {
		id, stillInitial := account(t, "pw-tx@example.com")
		addReset(t, pool, id, "four")
		addSession(t, pool, id, "tx-session")
		// Deleting the open resets is the last step of both changes.
		undo := dbtest.FailDeletes(t, pool, "password_resets")
		defer undo()

		require.Error(t, svc.ChangePassword(ctx, id, "fourth-pw-1"))
		require.Error(t, svc.SetPassword(ctx, id, "fifth-password-1"))
		stillInitial("password stays when the reset cleanup fails")
		assert.Equal(t, 1, countRows(t, pool, "sessions", id), "the log-out of both changes is rolled back")
	})

	t.Run("the user's own change ends every session, in the same transaction", func(t *testing.T) {
		id, stillInitial := account(t, "pw-own@example.com")
		bystander := dbtest.InsertUser(t, pool, "pw-own-bystander@example.com")
		addSession(t, pool, bystander, "own-b")
		addSession(t, pool, id, "own-current")
		addSession(t, pool, id, "own-other-1")
		addSession(t, pool, id, "own-other-2")
		addReset(t, pool, id, "own-reset")

		require.ErrorIs(t, svc.ChangePassword(ctx, id, "äääääää"), ErrPasswordTooShort)
		require.ErrorIs(t, svc.ChangePassword(ctx, 999999, "long enough pw"), ErrNotFound)
		stillInitial("a rejected password is not stored")
		assert.Equal(t, 3, countRows(t, pool, "sessions", id), "a rejected change ends no session")

		// The deletion of the sessions fails: nothing is changed.
		undo := dbtest.FailDeletes(t, pool, "sessions")
		require.Error(t, svc.ChangePassword(ctx, id, "second-pw-1"))
		undo()
		stillInitial("the password stays when the sessions cannot be ended")
		assert.Equal(t, 3, countRows(t, pool, "sessions", id), "every session stays")
		assert.Equal(t, 1, countRows(t, pool, "password_resets", id), "the open reset stays")

		// The deletion of the open resets fails, after the sessions: the
		// deleted sessions come back with the rollback.
		undo = dbtest.FailDeletes(t, pool, "password_resets")
		require.Error(t, svc.ChangePassword(ctx, id, "second-pw-1"))
		undo()
		stillInitial("the password stays when the resets cannot be deleted")
		assert.Equal(t, 3, countRows(t, pool, "sessions", id), "the session deletion is rolled back")

		require.NoError(t, svc.ChangePassword(ctx, id, "second-pw-1"))
		ok, err := svc.VerifyPassword(ctx, id, "second-pw-1")
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, 0, countRows(t, pool, "sessions", id), "no session is left, the current one included")
		assert.Equal(t, 0, countRows(t, pool, "password_resets", id))
		assert.Equal(t, 1, countRows(t, pool, "sessions", bystander), "another user's session is untouched")
	})
}

// --- Hinweis: LIKE wildcards in the admin search ---------------------------

func TestSearchTreatsWildcardsAsText(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	svc := NewService(pool)

	for _, email := range []string{
		"a_b@example.com",
		"axb@example.com",
		"50%off@example.com",
		"plain@example.com",
	} {
		dbtest.InsertUser(t, pool, email)
	}

	emails := func(query string) []string {
		t.Helper()
		rows, total, err := svc.Search(ctx, query, 50, 0)
		require.NoError(t, err, "query %q", query)
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.Email)
		}
		require.EqualValues(t, len(out), total, "count and list must agree for %q", query)
		return out
	}

	assert.ElementsMatch(t, []string{"a_b@example.com"}, emails("a_b"), "underscore is a literal")
	assert.ElementsMatch(t, []string{"a_b@example.com"}, emails("_"))
	assert.ElementsMatch(t, []string{"50%off@example.com"}, emails("%"), "percent is a literal")
	assert.ElementsMatch(t, []string{"50%off@example.com"}, emails("0%o"))
	assert.Empty(t, emails(`\`), "a backslash matches nothing and is no error")
	assert.Empty(t, emails(`plain\`))
	assert.Empty(t, emails(`%%%`))

	// Ordinary searches keep working, case-insensitively.
	assert.ElementsMatch(t, []string{"plain@example.com"}, emails("PLAIN"))
	assert.Len(t, emails(""), 4)
	assert.Len(t, emails("example.com"), 4)
	assert.Len(t, emails(strings.Repeat("z", 300)), 0)
}
