package db_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
)

func getTestDBURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("TUNNELD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TUNNELD_TEST_DATABASE_URL not set; skipping db integration test")
	}
	return url
}

func TestOpenAndPing(t *testing.T) {
	url := getTestDBURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, url)
	require.NoError(t, err)
	defer pool.Close()

	require.NoError(t, pool.Ping(ctx))
}

// The migration tests go through dbtest.Pool. It holds the lock that keeps
// the test binaries of other packages from migrating the same database at
// the same moment; two migrators at once fail with "already exists".

func TestMigrateUpIdempotent(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	require.NoError(t, db.MigrateUp(ctx, pool))
	require.NoError(t, db.MigrateUp(ctx, pool))
}

func hasColumn(t *testing.T, pool *pgxpool.Pool, table, column string) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM information_schema.columns
		 WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`,
		table, column).Scan(&n))
	return n == 1
}

// TestAPITokenExpiryMigrationDownAndUp rolls the schema back to the version
// before 20261114000001_api_tokens_expires_at and forward again.
func TestAPITokenExpiryMigrationDownAndUp(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	require.True(t, hasColumn(t, pool, "api_tokens", "expires_at"), "column exists after MigrateUp")

	// A token with an expiry, to see that down and up cope with data.
	uid := dbtest.InsertUser(t, pool, "migration@example.com")
	_, err := pool.Exec(ctx,
		`INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, expires_at)
		 VALUES ($1, 'm', '\x01', 'prefix', now() + interval '1 hour')`, uid)
	require.NoError(t, err)

	// MigrateUp leaves goose pointed at the embedded files; the directory on
	// disk holds the same ones.
	const before = 20260427000002 // users_is_admin, the migration before this one
	goose.SetBaseFS(os.DirFS("."))
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	downErr := goose.DownToContext(ctx, sqlDB, "migrations", before)
	gone := downErr == nil && !hasColumn(t, pool, "api_tokens", "expires_at")

	// Forward again before any assertion can stop the test, so that a
	// failure here does not leave the database behind for other packages.
	require.NoError(t, db.MigrateUp(ctx, pool))

	require.NoError(t, downErr, "down section")
	assert.True(t, gone, "down removes the column")
	assert.True(t, hasColumn(t, pool, "api_tokens", "expires_at"), "up adds it back")

	var expires *time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT expires_at FROM api_tokens WHERE user_id = $1`, uid).Scan(&expires))
	assert.Nil(t, expires, "the re-added column starts out NULL: the token does not expire")
}
