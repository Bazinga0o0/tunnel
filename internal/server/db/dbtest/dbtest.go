// Package dbtest provides shared test helpers for integration tests that
// need a real Postgres. Kept in its own package so production binaries don't
// pull in the testing stdlib.
package dbtest

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db"
)

// advisoryLockID is an arbitrary 64-bit constant; any two callers using the
// same ID serialize across processes via Postgres' session-level advisory lock.
const advisoryLockID int64 = 0x54554e4e454c4401 // "TUNNEL" + 0x01

// Within-process serialization. Across processes, we use pg_advisory_lock.
var processMu sync.Mutex

// Pool opens a pool, grabs an advisory lock on a dedicated standalone
// connection (so the shared pool isn't starved), runs MigrateUp, and
// truncates all tables. Requires TUNNELD_TEST_DATABASE_URL. Skips otherwise.
//
// Serialization layers:
//   - processMu serializes concurrent tests within this Go process.
//   - pg_advisory_lock serializes tests across processes (go test runs packages in parallel).
func Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TUNNELD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TUNNELD_TEST_DATABASE_URL not set")
	}
	return openPool(t, url)
}

// tb is what openPool needs from *testing.T. The test of this package
// passes its own implementation to see what a failing step leaves behind.
type tb interface {
	Helper()
	Cleanup(func())
	Errorf(format string, args ...any)
	FailNow()
}

// openPool does the work of Pool.
//
// Every lock is paired with its release at once, before the next step that
// can fail. A step that fails (it ends the test through FailNow) therefore
// leaves no lock behind: with a lock left, every later Pool call in the
// same test binary would wait for processMu until the test timeout, and
// other binaries would wait for the advisory lock.
func openPool(t tb, url string) *pgxpool.Pool {
	t.Helper()

	processMu.Lock()
	t.Cleanup(processMu.Unlock)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Dedicated standalone connection for the advisory lock. Kept out of the
	// shared pool so test code can open multiple pool connections freely.
	lockConn, err := pgx.Connect(ctx, url)
	require.NoError(t, err)
	// Registered before the lock is asked for: closing the connection ends
	// the session, and the advisory lock goes with it, also when the wait
	// for the lock was cut off by the timeout above.
	t.Cleanup(func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer releaseCancel()
		_, _ = lockConn.Exec(releaseCtx, "SELECT pg_advisory_unlock($1)", advisoryLockID)
		_ = lockConn.Close(releaseCtx)
	})
	_, err = lockConn.Exec(ctx, "SELECT pg_advisory_lock($1)", advisoryLockID)
	require.NoError(t, err)

	pool, err := db.Open(ctx, url)
	require.NoError(t, err)
	// The caller closes the pool it receives; a pool that is never handed
	// out is closed here.
	handedOut := false
	t.Cleanup(func() {
		if !handedOut {
			pool.Close()
		}
	})
	require.NoError(t, db.MigrateUp(ctx, pool))

	// A test binary that was killed (timeout) never ran the cleanup of
	// FailDeletes. Remove what it left behind, or every later run fails.
	_, err = pool.Exec(ctx, `DO $$
		DECLARE r record;
		BEGIN
			FOR r IN SELECT tgname, tgrelid::regclass AS rel FROM pg_trigger
			         WHERE NOT tgisinternal AND tgname LIKE 'dbtest\_fail\_delete\_%'
			LOOP
				EXECUTE format('DROP TRIGGER %I ON %s', r.tgname, r.rel);
			END LOOP;
		END $$`)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `TRUNCATE users, api_tokens, reserved_subdomains, reserved_tcp_ports, audit_log, sessions, email_verifications, password_resets RESTART IDENTITY CASCADE`)
	require.NoError(t, err)

	handedOut = true
	return pool
}

// InsertUser adds a user row directly and returns its id. The password hash
// is a placeholder that no password matches, so the row is for tests that
// need an account but never log in with it; they skip the cost of argon2.
func InsertUser(t *testing.T, pool *pgxpool.Pool, email string) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash) VALUES ($1, 'test-placeholder-not-a-hash') RETURNING id`,
		email).Scan(&id)
	require.NoError(t, err)
	return id
}

// FailDeletes makes every DELETE statement on table fail, by way of a
// statement-level trigger, until the returned function is called or the
// test ends. Tests use it to make one step in the middle of a transaction
// fail and then check that the earlier steps were rolled back.
//
// The pool must stay open until the cleanup has run: register pool.Close
// with t.Cleanup before calling FailDeletes instead of deferring it.
func FailDeletes(t *testing.T, pool *pgxpool.Pool, table string) (undo func()) {
	t.Helper()
	ctx := context.Background()
	name := pgx.Identifier{"dbtest_fail_delete_" + table}.Sanitize()
	target := pgx.Identifier{table}.Sanitize()

	undo = func() {
		_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+name+` ON `+target)
		_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS `+name+`()`)
	}
	undo() // leftovers of an earlier run that was killed
	t.Cleanup(undo)

	_, err := pool.Exec(ctx, `CREATE FUNCTION `+name+`() RETURNS trigger LANGUAGE plpgsql AS
		$$ BEGIN RAISE EXCEPTION 'dbtest: injected failure'; END $$`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `CREATE TRIGGER `+name+` BEFORE DELETE ON `+target+
		` FOR EACH STATEMENT EXECUTE FUNCTION `+name+`()`)
	require.NoError(t, err)
	return undo
}
