package users

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
)

// Switching a server from open to approval must not lock out anybody who is
// already using it: admins and every account with a token or a reservation
// are approved at start, everybody else waits.
func TestApproveExistingMarksExactlyTheRightAccounts(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	svc := NewService(pool)
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := pool.Exec(ctx, sql, args...)
		require.NoError(t, err)
	}

	admin := dbtest.InsertUser(t, pool, "admin@example.com")
	setFlags(t, pool, admin, true, false)
	withToken := dbtest.InsertUser(t, pool, "token@example.com")
	exec(`INSERT INTO api_tokens (user_id, name, token_hash, token_prefix) VALUES ($1, 'cli', '\x01', 'aaaaaaaa')`, withToken)
	withSubdomain := dbtest.InsertUser(t, pool, "subdomain@example.com")
	exec(`INSERT INTO reserved_subdomains (subdomain, user_id) VALUES ('kept', $1)`, withSubdomain)
	withTCP := dbtest.InsertUser(t, pool, "tcp@example.com")
	exec(`INSERT INTO reserved_tcp_ports (port, user_id) VALUES (20001, $1)`, withTCP)
	withUDP := dbtest.InsertUser(t, pool, "udp@example.com")
	exec(`INSERT INTO reserved_udp_ports (port, user_id) VALUES (20002, $1)`, withUDP)
	bareVerified := dbtest.InsertUser(t, pool, "verified@example.com")
	require.NoError(t, svc.MarkEmailVerified(ctx, bareVerified))
	bareUnverified := dbtest.InsertUser(t, pool, "unverified@example.com")

	n, err := svc.ApproveExisting(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 5, n)

	for _, c := range []struct {
		name     string
		id       int64
		approved bool
	}{
		{"admin", admin, true},
		{"with token", withToken, true},
		{"with subdomain", withSubdomain, true},
		{"with tcp port", withTCP, true},
		{"with udp port", withUDP, true},
		{"bare verified", bareVerified, false},
		{"bare unverified", bareUnverified, false},
	} {
		u, err := svc.FindByID(ctx, c.id)
		require.NoError(t, err)
		assert.Equal(t, c.approved, IsApproved(u), c.name)
	}

	n, err = svc.ApproveExisting(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 0, n, "second run approves nobody")
}

// Rejecting deletes a waiting account with everything that hangs on it, and
// nothing else: never an approved account, never an admin.
func TestDeletePendingRefusesApprovedAndAdmins(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	svc := NewService(pool)

	approved := dbtest.InsertUser(t, pool, "approved@example.com")
	require.NoError(t, svc.Approve(ctx, approved))
	admin := dbtest.InsertUser(t, pool, "admin@example.com") // admin, not approved
	setFlags(t, pool, admin, true, false)
	pending := dbtest.InsertUser(t, pool, "pending@example.com")
	addSession(t, pool, pending, "pending")
	bystander := dbtest.InsertUser(t, pool, "bystander@example.com")
	addSession(t, pool, bystander, "bystander")

	assert.ErrorIs(t, svc.DeletePending(ctx, approved), ErrNotPending)
	assert.ErrorIs(t, svc.DeletePending(ctx, admin), ErrNotPending)
	for _, id := range []int64{approved, admin} {
		_, err := svc.FindByID(ctx, id)
		assert.NoError(t, err, "refused delete keeps user %d", id)
	}

	require.NoError(t, svc.DeletePending(ctx, pending))
	_, err := svc.FindByID(ctx, pending)
	assert.ErrorIs(t, err, ErrNotFound)
	assert.Equal(t, 0, countRows(t, pool, "sessions", pending), "sessions of the deleted account")
	assert.Equal(t, 1, countRows(t, pool, "sessions", bystander), "another user's session is untouched")
}

// An account that holds a token or a reservation is in use, whatever
// approved_at says: before the first server start in approval or closed
// mode ApproveExisting has not run yet, and the admin CLI works on the
// database meanwhile. Rejecting such an account would delete its tokens and
// reservations with it, so DeletePending refuses it, and the list of
// waiting accounts leaves it out. A disabled account does not wait either.
func TestDeletePendingRefusesAccountsInUseAndDisabled(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	svc := NewService(pool)
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := pool.Exec(ctx, sql, args...)
		require.NoError(t, err)
	}

	revokedToken := dbtest.InsertUser(t, pool, "revoked-token@example.com")
	exec(`INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, revoked_at)
		VALUES ($1, 'cli', '\x01', 'aaaaaaaa', now())`, revokedToken)
	withSubdomain := dbtest.InsertUser(t, pool, "subdomain@example.com")
	exec(`INSERT INTO reserved_subdomains (subdomain, user_id) VALUES ('kept', $1)`, withSubdomain)
	withTCP := dbtest.InsertUser(t, pool, "tcp@example.com")
	exec(`INSERT INTO reserved_tcp_ports (port, user_id) VALUES (20001, $1)`, withTCP)
	withUDP := dbtest.InsertUser(t, pool, "udp@example.com")
	exec(`INSERT INTO reserved_udp_ports (port, user_id) VALUES (20002, $1)`, withUDP)
	disabled := dbtest.InsertUser(t, pool, "disabled@example.com")
	setFlags(t, pool, disabled, false, true)
	waiting := dbtest.InsertUser(t, pool, "waiting@example.com")

	pending, err := svc.ListPending(ctx)
	require.NoError(t, err)
	require.Len(t, pending, 1, "only the account that is not in use waits")
	assert.Equal(t, waiting, pending[0].ID)
	n, err := svc.CountPending(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 1, n, "the count of the menu item follows the list")

	for name, id := range map[string]int64{
		"revoked token": revokedToken, "subdomain": withSubdomain, "tcp port": withTCP,
		"udp port": withUDP, "disabled": disabled,
	} {
		assert.ErrorIs(t, svc.DeletePending(ctx, id), ErrNotPending, name)
		_, err := svc.FindByID(ctx, id)
		assert.NoError(t, err, "%s: the account stays", name)
	}
	assert.Equal(t, 1, countRows(t, pool, "api_tokens", revokedToken), "the token stays")
	assert.Equal(t, 1, countRows(t, pool, "reserved_subdomains", withSubdomain), "the reservation stays")

	require.NoError(t, svc.DeletePending(ctx, waiting))
	_, err = svc.FindByID(ctx, waiting)
	assert.ErrorIs(t, err, ErrNotFound, "the account that waits and owns nothing is rejected")
	assert.ErrorIs(t, svc.DeletePending(ctx, waiting), ErrNotPending, "an unknown id")
}

// A rejection that meets a transaction adding the account's first token
// waits for it and then leaves the account, with the token, alone. A plain
// DELETE would wait for the row as well and then delete by what it had
// seen before the wait: the account, and the new token with it.
func TestDeletePendingWaitsForAFirstTokenAndKeepsIt(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	svc := NewService(pool)
	id := dbtest.InsertUser(t, pool, "first-token@example.com")

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO api_tokens (user_id, name, token_hash, token_prefix)
		VALUES ($1, 'laptop', '\x02', 'bbbbbbbb')`, id)
	require.NoError(t, err)
	var inserter int32
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&inserter))

	done := make(chan error, 1)
	go func() { done <- svc.DeletePending(ctx, id) }()
	require.Eventually(t, func() bool {
		var waiting int
		err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'
			  AND $1::int = ANY(pg_blocking_pids(pid))`, inserter).Scan(&waiting)
		return err == nil && waiting > 0
	}, 10*time.Second, 10*time.Millisecond, "the rejection must wait for the account row")

	require.NoError(t, tx.Commit(ctx))
	select {
	case err := <-done:
		assert.ErrorIs(t, err, ErrNotPending, "the account holds a token now")
	case <-time.After(10 * time.Second):
		t.Fatal("the rejection did not finish after the insert was committed")
	}
	_, err = svc.FindByID(ctx, id)
	assert.NoError(t, err, "the account stays")
	assert.Equal(t, 1, countRows(t, pool, "api_tokens", id), "the token stays")
}
