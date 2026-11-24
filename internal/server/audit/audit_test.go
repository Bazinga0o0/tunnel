package audit

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func TestLogAndList(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, err := userSvc.Create(ctx, "audit@example.com", "pw12345678")
	require.NoError(t, err)

	svc := NewService(pool)
	ip := netip.MustParseAddr("1.2.3.4")
	require.NoError(t, svc.Log(ctx, &u.ID, "login", map[string]any{"user_agent": "test"}, ip))
	require.NoError(t, svc.Log(ctx, &u.ID, "token.create", map[string]any{"name": "laptop"}, ip))

	entries, err := svc.ListByUser(ctx, u.ID, 10)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, "token.create", entries[0].Action) // newest first
	assert.Equal(t, "login", entries[1].Action)
}

func TestLogAllowsNilUserID(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	svc := NewService(pool)
	ip := netip.MustParseAddr("1.2.3.4")
	require.NoError(t, svc.Log(ctx, nil, "signup.attempt", map[string]any{"email": "nope@example.com"}, ip))
}
