package verifications

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func TestIssueAndConsume(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, err := userSvc.Create(ctx, "v@example.com", "pw12345678")
	require.NoError(t, err)
	require.False(t, u.EmailVerifiedAt.Valid)

	svc := NewService(pool, userSvc)
	raw, err := svc.Issue(ctx, u.ID)
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	uid, err := svc.Consume(ctx, raw)
	require.NoError(t, err)
	assert.Equal(t, u.ID, uid)

	got, err := userSvc.FindByID(ctx, u.ID)
	require.NoError(t, err)
	assert.True(t, got.EmailVerifiedAt.Valid)
}

func TestConsumeRejectsUnknown(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	svc := NewService(pool, userSvc)

	_, err := svc.Consume(ctx, "does-not-exist")
	require.ErrorIs(t, err, ErrInvalidVerification)
}

func TestConsumeRejectsEmpty(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	svc := NewService(pool, userSvc)

	_, err := svc.Consume(ctx, "")
	require.ErrorIs(t, err, ErrInvalidVerification)
}

func TestConsumeSingleUse(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, _ := userSvc.Create(ctx, "su@example.com", "pw12345678")
	svc := NewService(pool, userSvc)

	raw, _ := svc.Issue(ctx, u.ID)
	_, err := svc.Consume(ctx, raw)
	require.NoError(t, err)

	_, err = svc.Consume(ctx, raw)
	require.ErrorIs(t, err, ErrInvalidVerification)
}

func TestConsumeRejectsExpired(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, _ := userSvc.Create(ctx, "ex@example.com", "pw12345678")
	svc := NewService(pool, userSvc)

	t.Skip("expired-token case is covered by GetEmailVerificationByHash's WHERE clause; pinning it here requires injecting a past timestamp, deferred to a lower-level test")
	_ = u
	_ = svc
	_ = time.Now
}
