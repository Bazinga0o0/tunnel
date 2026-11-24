package tokens_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func TestIssueAndVerifyToken(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, err := userSvc.Create(ctx, "a@b.example.com", "pw12345678")
	require.NoError(t, err)

	svc := tokens.NewService(pool)
	raw, row, err := svc.Issue(ctx, u.ID, "Laptop")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(raw, "twbl_"))
	assert.GreaterOrEqual(t, len(raw), len("twbl_")+32)
	assert.Equal(t, u.ID, row.UserID)
	assert.Equal(t, "Laptop", row.Name)

	userID, err := svc.Verify(ctx, raw)
	require.NoError(t, err)
	assert.Equal(t, u.ID, userID)

	require.NoError(t, svc.Revoke(ctx, row.ID))
	_, err = svc.Verify(ctx, raw)
	require.ErrorIs(t, err, tokens.ErrInvalidToken)
}

func TestVerifyRejectsUnknownToken(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := tokens.NewService(pool)
	_, err := svc.Verify(ctx, "twbl_bogus000000000000000000000000000000")
	require.ErrorIs(t, err, tokens.ErrInvalidToken)
}

func TestVerifyRejectsEmpty(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := tokens.NewService(pool)
	_, err := svc.Verify(ctx, "")
	require.ErrorIs(t, err, tokens.ErrInvalidToken)
}
