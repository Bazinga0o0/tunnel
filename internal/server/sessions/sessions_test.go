package sessions

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func TestCreateAndLookup(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	u, err := users.NewService(pool).Create(ctx, "s@example.com", "pw12345678")
	require.NoError(t, err)

	svc := NewService(pool)
	ip := netip.MustParseAddr("1.2.3.4")
	raw, row, err := svc.Create(ctx, u.ID, "test-agent", ip, 24*time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, raw)
	assert.Equal(t, u.ID, row.UserID)

	got, err := svc.Lookup(ctx, raw)
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.UserID)
}

func TestLookupRejectsExpired(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	u, _ := users.NewService(pool).Create(ctx, "exp@example.com", "pw12345678")
	svc := NewService(pool)
	raw, _, err := svc.Create(ctx, u.ID, "", netip.Addr{}, -1*time.Minute)
	require.NoError(t, err)

	_, err = svc.Lookup(ctx, raw)
	require.ErrorIs(t, err, ErrInvalidSession)
}

func TestLookupRejectsEmpty(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	_, err := svc.Lookup(ctx, "")
	require.ErrorIs(t, err, ErrInvalidSession)
}

func TestDeleteInvalidates(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	u, _ := users.NewService(pool).Create(ctx, "d@example.com", "pw12345678")
	svc := NewService(pool)
	raw, row, _ := svc.Create(ctx, u.ID, "", netip.Addr{}, time.Hour)

	require.NoError(t, svc.Delete(ctx, row.ID))
	_, err := svc.Lookup(ctx, raw)
	require.ErrorIs(t, err, ErrInvalidSession)
}

func TestDeleteAllForUser(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	u, _ := users.NewService(pool).Create(ctx, "d2@example.com", "pw12345678")
	svc := NewService(pool)
	raw1, _, _ := svc.Create(ctx, u.ID, "", netip.Addr{}, time.Hour)
	raw2, _, _ := svc.Create(ctx, u.ID, "", netip.Addr{}, time.Hour)

	require.NoError(t, svc.DeleteAllForUser(ctx, u.ID))

	_, err := svc.Lookup(ctx, raw1)
	require.ErrorIs(t, err, ErrInvalidSession)
	_, err = svc.Lookup(ctx, raw2)
	require.ErrorIs(t, err, ErrInvalidSession)
}
