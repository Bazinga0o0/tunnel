package reservations

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func TestRevokeTCPPortReturningOwner(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	uid := newUser(t, users.NewService(pool), "revoke-owner@example.com")
	svc := NewService(pool)
	require.NoError(t, svc.GrantTCPPort(ctx, 15000, uid))
	require.NoError(t, svc.GrantTCPPort(ctx, 15001, uid))

	owner, reserved, err := svc.RevokeTCPPortReturningOwner(ctx, 15000)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, uid, owner)
	_, reserved, err = svc.OwnerTCPPort(ctx, 15000)
	require.NoError(t, err)
	assert.False(t, reserved, "the reservation is gone")
	owner, reserved, err = svc.OwnerTCPPort(ctx, 15001)
	require.NoError(t, err)
	assert.True(t, reserved, "only the named port is revoked")
	assert.Equal(t, uid, owner)

	// Nothing reserved: no owner, no error.
	owner, reserved, err = svc.RevokeTCPPortReturningOwner(ctx, 15000)
	require.NoError(t, err)
	assert.False(t, reserved)
	assert.Zero(t, owner)

	for _, port := range []int{0, -1, 65536} {
		owner, reserved, err = svc.RevokeTCPPortReturningOwner(ctx, port)
		assert.ErrorIs(t, err, ErrInvalidPort, "port %d", port)
		assert.False(t, reserved)
		assert.Zero(t, owner)
	}
}

// The revoke reads and deletes in one step: a transfer of the port that
// commits while the revoke waits for the row is removed with it, and the
// revoke names the owner the transfer set, not the one before.
func TestRevokeTCPPortReturningOwnerReportsTheOwnerItRemoved(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	us := users.NewService(pool)
	a := newUser(t, us, "revoke-a@example.com")
	b := newUser(t, us, "revoke-b@example.com")
	svc := NewService(pool)
	const port = 15002
	require.NoError(t, svc.GrantTCPPort(ctx, port, a))

	// A transfer to b, as TransferTCPPort makes it, that has not committed.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SELECT user_id FROM reserved_tcp_ports WHERE port = $1 FOR UPDATE`, port)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `UPDATE reserved_tcp_ports SET user_id = $2 WHERE port = $1`, port, b)
	require.NoError(t, err)
	var transfer int32
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&transfer))

	type result struct {
		owner    int64
		reserved bool
		err      error
	}
	done := make(chan result, 1)
	go func() {
		owner, reserved, err := svc.RevokeTCPPortReturningOwner(ctx, port)
		done <- result{owner, reserved, err}
	}()
	// The revoke waits for the transfer's row lock: one session waits for a
	// lock that the transfer's server process holds. Only those count; any
	// other session that waits for a lock in this database (another test
	// binary at the advisory lock of dbtest, say) has nothing to do with it.
	require.Eventually(t, func() bool {
		var waiting int
		err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'
			  AND $1::int = ANY(pg_blocking_pids(pid))`, transfer).Scan(&waiting)
		return err == nil && waiting == 1
	}, 10*time.Second, 10*time.Millisecond, "the revoke never waited for the row lock")
	require.NoError(t, tx.Commit(ctx))

	select {
	case r := <-done:
		require.NoError(t, r.err)
		assert.True(t, r.reserved)
		assert.Equal(t, b, r.owner, "the owner the revoke removed, set by the transfer")
	case <-time.After(10 * time.Second):
		t.Fatal("the revoke did not return after the transfer committed")
	}
	_, reserved, err := svc.OwnerTCPPort(ctx, port)
	require.NoError(t, err)
	assert.False(t, reserved)
}
