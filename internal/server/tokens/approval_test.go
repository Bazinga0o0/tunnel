package tokens_test

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
)

// A token of an account that waits for approval opens no tunnel and keeps
// no session alive while approval is required; without the requirement it
// works as before. The token is written directly, past every check that
// should keep a waiting account from getting one.
func TestVerifyRefusesTokenOfPendingAccountWhenRequired(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	uid := dbtest.InsertUser(t, pool, "pending@example.com")
	raw := tokens.TokenPrefix + "pendingPendingPendingPendingPend"
	hash := sha256.Sum256([]byte(raw))
	var tokenID int64
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO api_tokens (user_id, name, token_hash, token_prefix) VALUES ($1, 'cli', $2, 'pendingP') RETURNING id`,
		uid, hash[:]).Scan(&tokenID))

	strict := tokens.NewServiceWithOptions(pool, tokens.Options{RequireApproved: true})
	lax := tokens.NewServiceWithOptions(pool, tokens.Options{})

	_, _, err := strict.VerifyWithID(ctx, raw)
	assert.ErrorIs(t, err, tokens.ErrInvalidToken, "required: pending account's token")
	invalid, err := strict.InvalidTokenIDs(ctx, []int64{tokenID})
	require.NoError(t, err)
	assert.Equal(t, []int64{tokenID}, invalid, "required: running session of a pending account")

	gotUser, gotToken, err := lax.VerifyWithID(ctx, raw)
	require.NoError(t, err, "not required: pending account's token")
	assert.Equal(t, uid, gotUser)
	assert.Equal(t, tokenID, gotToken)
	invalid, err = lax.InvalidTokenIDs(ctx, []int64{tokenID})
	require.NoError(t, err)
	assert.Empty(t, invalid, "not required: running session of a pending account")

	_, err = pool.Exec(ctx, `UPDATE users SET approved_at = now() WHERE id = $1`, uid)
	require.NoError(t, err)
	gotUser, _, err = strict.VerifyWithID(ctx, raw)
	require.NoError(t, err, "required: approved account's token")
	assert.Equal(t, uid, gotUser)
}
