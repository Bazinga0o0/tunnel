package reservations

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func TestReserveAndOwner(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, err := userSvc.Create(ctx, "a@b.example.com", "pw12345678")
	require.NoError(t, err)

	svc := NewService(pool)

	// Not reserved yet.
	owner, reserved, err := svc.Owner(ctx, "myapp")
	require.NoError(t, err)
	assert.False(t, reserved)
	assert.Zero(t, owner)

	// Reserve.
	require.NoError(t, svc.Reserve(ctx, "myapp", u.ID))

	owner, reserved, err = svc.Owner(ctx, "myapp")
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, u.ID, owner)
}

func TestReserveRejectsDuplicate(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u1, _ := userSvc.Create(ctx, "u1@example.com", "pw12345678")
	u2, _ := userSvc.Create(ctx, "u2@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.Reserve(ctx, "shared", u1.ID))
	err := svc.Reserve(ctx, "shared", u2.ID)
	require.ErrorIs(t, err, ErrAlreadyReserved)
}

func TestReleaseOnlyByOwner(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u1, _ := userSvc.Create(ctx, "u1@example.com", "pw12345678")
	u2, _ := userSvc.Create(ctx, "u2@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.Reserve(ctx, "foo", u1.ID))

	// Other user cannot release.
	err := svc.Release(ctx, "foo", u2.ID)
	require.ErrorIs(t, err, ErrNotOwned)

	_, reserved, _ := svc.Owner(ctx, "foo")
	assert.True(t, reserved)

	// Owner can release.
	require.NoError(t, svc.Release(ctx, "foo", u1.ID))
	_, reserved, _ = svc.Owner(ctx, "foo")
	assert.False(t, reserved)
}

func TestReleaseIgnoresUnreserved(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, _ := userSvc.Create(ctx, "u@example.com", "pw12345678")

	svc := NewService(pool)
	// No error releasing a subdomain that was never reserved.
	require.NoError(t, svc.Release(ctx, "never-reserved", u.ID))
}

// --- UDP port reservation tests ---

func TestReserveUDPPortHappy(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, err := userSvc.Create(ctx, "udp-a@example.com", "pw12345678")
	require.NoError(t, err)

	svc := NewService(pool)

	// Not reserved yet.
	owner, reserved, err := svc.OwnerUDPPort(ctx, 35000)
	require.NoError(t, err)
	assert.False(t, reserved)
	assert.Zero(t, owner)

	// Reserve.
	require.NoError(t, svc.ReserveUDPPort(ctx, 35000, u.ID))

	owner, reserved, err = svc.OwnerUDPPort(ctx, 35000)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, u.ID, owner)

	// ListUDPPortsByUser should contain the port.
	ports, err := svc.ListUDPPortsByUser(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, ports, 1)
	assert.Equal(t, int32(35000), ports[0].Port)
}

func TestReserveUDPPortConflict(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u1, _ := userSvc.Create(ctx, "udp-u1@example.com", "pw12345678")
	u2, _ := userSvc.Create(ctx, "udp-u2@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.ReserveUDPPort(ctx, 35001, u1.ID))
	err := svc.ReserveUDPPort(ctx, 35001, u2.ID)
	require.ErrorIs(t, err, ErrAlreadyReserved)
}

func TestReleaseUDPPortNotOwned(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u1, _ := userSvc.Create(ctx, "udp-u1b@example.com", "pw12345678")
	u2, _ := userSvc.Create(ctx, "udp-u2b@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.ReserveUDPPort(ctx, 35002, u1.ID))

	// Other user cannot release.
	err := svc.ReleaseUDPPort(ctx, 35002, u2.ID)
	require.ErrorIs(t, err, ErrNotOwned)

	_, reserved, _ := svc.OwnerUDPPort(ctx, 35002)
	assert.True(t, reserved)

	// Owner can release.
	require.NoError(t, svc.ReleaseUDPPort(ctx, 35002, u1.ID))
	_, reserved, _ = svc.OwnerUDPPort(ctx, 35002)
	assert.False(t, reserved)
}

// --- Admin ListAll tests ---

func TestListAllSubdomains(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u1, _ := userSvc.Create(ctx, "la-u1@example.com", "pw12345678")
	u2, _ := userSvc.Create(ctx, "la-u2@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.Reserve(ctx, "alpha", u1.ID))
	require.NoError(t, svc.Reserve(ctx, "beta", u2.ID))

	all, err := svc.ListAllSubdomains(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2)
}

func TestListAllTCPPorts(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, _ := userSvc.Create(ctx, "la-tcp@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.ReserveTCPPort(ctx, 36001, u.ID))
	require.NoError(t, svc.ReserveTCPPort(ctx, 36002, u.ID))

	all, err := svc.ListAllTCPPorts(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2)
}

func TestListAllUDPPorts(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, _ := userSvc.Create(ctx, "la-udp@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.ReserveUDPPort(ctx, 37001, u.ID))

	all, err := svc.ListAllUDPPorts(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1)
}

// --- Admin Grant tests ---

func TestGrantSubdomain(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, _ := userSvc.Create(ctx, "grant-sd@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.GrantSubdomain(ctx, "granted", u.ID))

	owner, reserved, err := svc.Owner(ctx, "granted")
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, u.ID, owner)
}

func TestGrantSubdomainConflict(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u1, _ := userSvc.Create(ctx, "grant-sd-c1@example.com", "pw12345678")
	u2, _ := userSvc.Create(ctx, "grant-sd-c2@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.GrantSubdomain(ctx, "taken", u1.ID))
	err := svc.GrantSubdomain(ctx, "taken", u2.ID)
	require.ErrorIs(t, err, ErrAlreadyReserved)
}

func TestGrantTCPPort(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, _ := userSvc.Create(ctx, "grant-tcp@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.GrantTCPPort(ctx, 38001, u.ID))

	owner, reserved, err := svc.OwnerTCPPort(ctx, 38001)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, u.ID, owner)
}

func TestGrantUDPPort(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, _ := userSvc.Create(ctx, "grant-udp@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.GrantUDPPort(ctx, 39001, u.ID))

	owner, reserved, err := svc.OwnerUDPPort(ctx, 39001)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, u.ID, owner)
}

// --- Admin Revoke tests ---

func TestRevokeSubdomain(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, _ := userSvc.Create(ctx, "revoke-sd@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.Reserve(ctx, "torevoke", u.ID))
	require.NoError(t, svc.RevokeSubdomain(ctx, "torevoke"))

	_, reserved, _ := svc.Owner(ctx, "torevoke")
	assert.False(t, reserved)
}

func TestRevokeSubdomainNoOp(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	// Revoking a non-existent subdomain is a no-op (no error).
	require.NoError(t, svc.RevokeSubdomain(ctx, "never-existed"))
}

func TestRevokeTCPPort(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, _ := userSvc.Create(ctx, "revoke-tcp@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.ReserveTCPPort(ctx, 40001, u.ID))
	require.NoError(t, svc.RevokeTCPPort(ctx, 40001))

	_, reserved, _ := svc.OwnerTCPPort(ctx, 40001)
	assert.False(t, reserved)
}

func TestRevokeUDPPort(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, _ := userSvc.Create(ctx, "revoke-udp@example.com", "pw12345678")

	svc := NewService(pool)
	require.NoError(t, svc.ReserveUDPPort(ctx, 41001, u.ID))
	require.NoError(t, svc.RevokeUDPPort(ctx, 41001))

	_, reserved, _ := svc.OwnerUDPPort(ctx, 41001)
	assert.False(t, reserved)
}
