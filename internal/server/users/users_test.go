package users

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
)

// fakeSessionPurger records which user IDs it was asked to purge.
type fakeSessionPurger struct {
	purged []int64
}

func (f *fakeSessionPurger) DeleteAllForUser(_ context.Context, userID int64) error {
	f.purged = append(f.purged, userID)
	return nil
}

func TestCreateAndFindByEmail(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	u, err := svc.Create(ctx, "Alice@Example.com", "correct horse")
	require.NoError(t, err)
	require.NotZero(t, u.ID)

	got, err := svc.FindByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, u.ID, got.ID)
}

func TestVerifyPassword(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	u, err := svc.Create(ctx, "bob@example.com", "hunter2!!")
	require.NoError(t, err)

	ok, err := svc.VerifyPassword(ctx, u.ID, "hunter2!!")
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = svc.VerifyPassword(ctx, u.ID, "wrong")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestCreateRejectsDuplicate(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	_, err := svc.Create(ctx, "dup@example.com", "pw-12345678")
	require.NoError(t, err)
	_, err = svc.Create(ctx, "dup@example.com", "pw-12345678")
	require.ErrorIs(t, err, ErrEmailTaken)
}

func TestFindByEmailNotFound(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	_, err := svc.FindByEmail(ctx, "nobody@example.com")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestPromoteAndIsAdmin(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	u, err := svc.Create(ctx, "promote@example.com", "pw12345678")
	require.NoError(t, err)

	ok, err := svc.IsAdmin(ctx, u.ID)
	require.NoError(t, err)
	assert.False(t, ok)

	require.NoError(t, svc.Promote(ctx, u.ID))

	ok, err = svc.IsAdmin(ctx, u.ID)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestDemoteBlocksLastAdmin(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	u, err := svc.Create(ctx, "lastadmin@example.com", "pw12345678")
	require.NoError(t, err)
	require.NoError(t, svc.Promote(ctx, u.ID))

	err = svc.Demote(ctx, u.ID)
	require.ErrorIs(t, err, ErrLastAdmin)

	// Adding a second admin allows demoting the first.
	u2, err := svc.Create(ctx, "admin2@example.com", "pw12345678")
	require.NoError(t, err)
	require.NoError(t, svc.Promote(ctx, u2.ID))

	require.NoError(t, svc.Demote(ctx, u.ID))
	ok, err := svc.IsAdmin(ctx, u.ID)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestDisablePurgesSessions(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	u, err := svc.Create(ctx, "disable@example.com", "pw12345678")
	require.NoError(t, err)
	addSession(t, pool, u.ID, "legacy")

	// A purger that is passed in is no longer called: Disable deletes the
	// sessions itself, inside its transaction.
	purger := &fakeSessionPurger{}
	require.NoError(t, svc.Disable(ctx, purger, u.ID))

	assert.Empty(t, purger.purged)
	assert.Equal(t, 0, countRows(t, pool, "sessions", u.ID))

	// User should now be disabled.
	got, err := svc.FindByID(ctx, u.ID)
	require.NoError(t, err)
	assert.True(t, got.DisabledAt.Valid)
}

func TestEnableUser(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	u, err := svc.Create(ctx, "enable@example.com", "pw12345678")
	require.NoError(t, err)

	require.NoError(t, svc.Disable(ctx, nil, u.ID))

	got, err := svc.FindByID(ctx, u.ID)
	require.NoError(t, err)
	assert.True(t, got.DisabledAt.Valid)

	require.NoError(t, svc.Enable(ctx, u.ID))
	got, err = svc.FindByID(ctx, u.ID)
	require.NoError(t, err)
	assert.False(t, got.DisabledAt.Valid)
}

func TestSetPassword(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	u, err := svc.Create(ctx, "setpw@example.com", "initialpw1")
	require.NoError(t, err)

	require.NoError(t, svc.SetPassword(ctx, u.ID, "newpassword1"))

	ok, err := svc.VerifyPassword(ctx, u.ID, "newpassword1")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = svc.VerifyPassword(ctx, u.ID, "initialpw1")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestIsAdminReturnsFalseForMissingUser(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	ok, err := svc.IsAdmin(ctx, 999999)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestLookupEmails(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	u1, err := svc.Create(ctx, "lookup1@example.com", "pw12345678")
	require.NoError(t, err)
	u2, err := svc.Create(ctx, "lookup2@example.com", "pw12345678")
	require.NoError(t, err)

	// Known IDs resolve to emails (stored lowercase).
	m, err := svc.LookupEmails(ctx, []int64{u1.ID, u2.ID})
	require.NoError(t, err)
	assert.Equal(t, "lookup1@example.com", m[u1.ID])
	assert.Equal(t, "lookup2@example.com", m[u2.ID])

	// Unknown ID is silently absent.
	m2, err := svc.LookupEmails(ctx, []int64{u1.ID, 999999})
	require.NoError(t, err)
	assert.Len(t, m2, 1)
	assert.Equal(t, "lookup1@example.com", m2[u1.ID])

	// Empty slice returns empty map without error.
	m3, err := svc.LookupEmails(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, m3)
}
