package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func TestDBVerifier(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, err := userSvc.Create(ctx, "v@example.com", "pw12345678")
	require.NoError(t, err)

	tokenSvc := tokens.NewService(pool)
	raw, _, err := tokenSvc.Issue(ctx, u.ID, "test")
	require.NoError(t, err)

	v := auth.NewDBVerifier(tokenSvc)

	uid, ok := v.VerifyWithUser(ctx, raw)
	assert.True(t, ok)
	assert.Equal(t, u.ID, uid)

	_, ok = v.VerifyWithUser(ctx, "twbl_definitely-not-a-real-token-00000000")
	assert.False(t, ok)

	_, ok = v.VerifyWithUser(ctx, "")
	assert.False(t, ok)
}

func TestDBVerifierVerifyWithToken(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	uid := dbtest.InsertUser(t, pool, "with-token@example.com")
	tokenSvc := tokens.NewService(pool)
	raw, row, err := tokenSvc.Issue(ctx, uid, "laptop")
	require.NoError(t, err)
	raw2, row2, err := tokenSvc.Issue(ctx, uid, "desktop")
	require.NoError(t, err)
	v := auth.NewDBVerifier(tokenSvc)

	gotUser, gotToken, ok := v.VerifyWithToken(ctx, raw)
	require.True(t, ok)
	assert.Equal(t, uid, gotUser)
	assert.Equal(t, row.ID, gotToken)

	gotUser, gotToken, ok = v.VerifyWithToken(ctx, raw2)
	require.True(t, ok)
	assert.Equal(t, uid, gotUser)
	assert.Equal(t, row2.ID, gotToken, "the id of the token that was presented")

	rejected := func(name, candidate string) {
		t.Helper()
		gotUser, gotToken, ok := v.VerifyWithToken(ctx, candidate)
		assert.False(t, ok, name)
		assert.Zero(t, gotUser, name)
		assert.Zero(t, gotToken, name)
		_, ok = v.VerifyWithUser(ctx, candidate)
		assert.False(t, ok, name+" (VerifyWithUser)")
	}
	rejected("empty", "")
	rejected("unknown", "twbl_definitely-not-a-real-token-00000000")

	// Expired.
	_, err = pool.Exec(ctx, `UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE id = $1`, row2.ID)
	require.NoError(t, err)
	rejected("expired", raw2)

	// Revoked.
	changed, err := tokenSvc.RevokeForUser(ctx, uid, row2.ID)
	require.NoError(t, err)
	require.True(t, changed)
	rejected("revoked", raw2)

	// Owner disabled: the token that was fine a moment ago stops working.
	_, _, ok = v.VerifyWithToken(ctx, raw)
	require.True(t, ok)
	_, err = pool.Exec(ctx, `UPDATE users SET disabled_at = now() WHERE id = $1`, uid)
	require.NoError(t, err)
	rejected("owner disabled", raw)

	// A database failure is a refusal, not a pass.
	pool.Close()
	rejected("database unavailable", raw)
}
