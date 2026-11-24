package passwordreset

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func TestIssueAndConsume(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	sessSvc := sessions.NewService(pool)
	u, err := userSvc.Create(ctx, "r@example.com", "oldpw1234")
	require.NoError(t, err)

	// Give the user an active session so Consume can invalidate it.
	_, _, err = sessSvc.Create(ctx, u.ID, "", netip.Addr{}, time.Hour)
	require.NoError(t, err)

	svc := NewService(pool, userSvc, sessSvc)
	raw, uid, err := svc.Issue(ctx, "r@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	assert.Equal(t, u.ID, uid)

	gotUID, err := svc.Consume(ctx, raw, "newpw5678")
	require.NoError(t, err)
	assert.Equal(t, u.ID, gotUID)

	// New password works.
	ok, err := userSvc.VerifyPassword(ctx, u.ID, "newpw5678")
	require.NoError(t, err)
	assert.True(t, ok)

	// Old password rejected.
	ok, err = userSvc.VerifyPassword(ctx, u.ID, "oldpw1234")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestIssueUnknownEmailReturnsEmpty(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	sessSvc := sessions.NewService(pool)
	svc := NewService(pool, userSvc, sessSvc)

	raw, uid, err := svc.Issue(ctx, "nobody@example.com")
	require.NoError(t, err) // no account enumeration
	assert.Empty(t, raw)
	assert.Zero(t, uid)
}

func TestConsumeRejectsUnknown(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	sessSvc := sessions.NewService(pool)
	svc := NewService(pool, userSvc, sessSvc)

	_, err := svc.Consume(ctx, "does-not-exist", "newpw5678")
	require.ErrorIs(t, err, ErrInvalidReset)
}

func TestConsumeRejectsEmpty(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	sessSvc := sessions.NewService(pool)
	svc := NewService(pool, userSvc, sessSvc)

	_, err := svc.Consume(ctx, "", "newpw5678")
	require.ErrorIs(t, err, ErrInvalidReset)
}

func TestConsumeRejectsShortPassword(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	sessSvc := sessions.NewService(pool)
	u, _ := userSvc.Create(ctx, "s@example.com", "oldpw1234")
	svc := NewService(pool, userSvc, sessSvc)
	raw, _, _ := svc.Issue(ctx, "s@example.com")

	_, err := svc.Consume(ctx, raw, "short")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 8")

	// Old password should still work — the weak password never landed.
	ok, err := userSvc.VerifyPassword(ctx, u.ID, "oldpw1234")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestConsumeSingleUse(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	sessSvc := sessions.NewService(pool)
	_, err := userSvc.Create(ctx, "su@example.com", "oldpw1234")
	require.NoError(t, err)

	svc := NewService(pool, userSvc, sessSvc)
	raw, _, _ := svc.Issue(ctx, "su@example.com")

	_, err = svc.Consume(ctx, raw, "newpw5678")
	require.NoError(t, err)

	_, err = svc.Consume(ctx, raw, "anotherpw1234")
	require.ErrorIs(t, err, ErrInvalidReset)
}
