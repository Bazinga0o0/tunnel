package reaper

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func TestSweepDeletesExpiredRows(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, err := userSvc.Create(ctx, "reap@example.com", "pw12345678")
	require.NoError(t, err)

	sessSvc := sessions.NewService(pool)

	// Live session (doesn't get reaped).
	_, liveRow, err := sessSvc.Create(ctx, u.ID, "", netip.Addr{}, time.Hour)
	require.NoError(t, err)

	// Expired session: insert directly via sqlc with an expiry one minute
	// before the database's now.
	q := sqlcgen.New(pool)
	deadHash := sha256.Sum256([]byte("dead"))
	_, err = q.CreateSession(ctx, sqlcgen.CreateSessionParams{
		ID:         deadHash[:],
		UserID:     u.ID,
		TtlSeconds: -60,
	})
	require.NoError(t, err)

	// Expired email verification.
	vHash := sha256.Sum256([]byte("v-dead"))
	err = q.CreateEmailVerification(ctx, sqlcgen.CreateEmailVerificationParams{
		TokenHash:  vHash[:],
		UserID:     u.ID,
		TtlSeconds: -60,
	})
	require.NoError(t, err)

	// Expired password reset.
	pHash := sha256.Sum256([]byte("p-dead"))
	err = q.CreatePasswordReset(ctx, sqlcgen.CreatePasswordResetParams{
		TokenHash:  pHash[:],
		UserID:     u.ID,
		TtlSeconds: -60,
	})
	require.NoError(t, err)

	r := New(pool, time.Hour, nil)
	r.Sweep(ctx)

	// Live session still there.
	_, err = q.GetSessionByID(ctx, liveRow.ID)
	require.NoError(t, err)

	// Expired rows gone — GetSessionByID's WHERE clause already filters, so
	// query the raw table count.
	var expiredSessionCount int
	require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE id = $1`, deadHash[:]).Scan(&expiredSessionCount))
	assert.Equal(t, 0, expiredSessionCount)

	var vCount int
	require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_verifications WHERE token_hash = $1`, vHash[:]).Scan(&vCount))
	assert.Equal(t, 0, vCount)

	var pCount int
	require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM password_resets WHERE token_hash = $1`, pHash[:]).Scan(&pCount))
	assert.Equal(t, 0, pCount)
}

func TestRunExitsOnContextCancel(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()

	ctx, cancel := context.WithCancel(context.Background())
	r := New(pool, 10*time.Millisecond, nil)

	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	// Give it a moment to do an initial sweep and start ticking.
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after ctx cancel")
	}
}
