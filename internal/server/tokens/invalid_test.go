package tokens_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
)

// InvalidTokenIDs is the query of the server's session revalidation: which of
// the token IDs of the live sessions can no longer be used.
func TestInvalidTokenIDs(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	svc := tokens.NewService(pool)

	issue := func(email string) (userID, tokenID int64) {
		t.Helper()
		uid := dbtest.InsertUser(t, pool, email)
		_, row, err := svc.Issue(ctx, uid, "laptop")
		require.NoError(t, err)
		return uid, row.ID
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		tag, err := pool.Exec(ctx, sql, args...)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected(), sql)
	}

	_, valid := issue("valid@example.com")
	_, revoked := issue("revoked@example.com")
	exec(`UPDATE api_tokens SET revoked_at = now() WHERE id = $1`, revoked)
	_, expired := issue("expired@example.com")
	expire(t, pool, expired, -time.Second)
	disabledUser, ofDisabled := issue("disabled@example.com")
	setDisabled(t, pool, disabledUser, true)
	_, deleted := issue("deleted@example.com")
	exec(`DELETE FROM api_tokens WHERE id = $1`, deleted)
	_, notYetExpired := issue("later@example.com")
	expire(t, pool, notYetExpired, time.Hour)
	unknown := deleted + 1000

	invalid, err := svc.InvalidTokenIDs(ctx, []int64{valid, revoked, expired, ofDisabled, deleted, notYetExpired, unknown, valid})
	require.NoError(t, err)
	assert.Equal(t, []int64{revoked, expired, ofDisabled, deleted, unknown}, invalid,
		"revoked, expired, owner disabled, deleted and unknown tokens, in the order given; valid ones not")

	invalid, err = svc.InvalidTokenIDs(ctx, []int64{valid, notYetExpired})
	require.NoError(t, err)
	assert.Empty(t, invalid)

	invalid, err = svc.InvalidTokenIDs(ctx, []int64{revoked, valid, revoked, unknown, unknown})
	require.NoError(t, err)
	assert.Equal(t, []int64{revoked, unknown}, invalid, "each invalid ID once")

	invalid, err = svc.InvalidTokenIDs(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, invalid)

	// A failing query is an error, never a verdict about the tokens.
	pool.Close()
	invalid, err = svc.InvalidTokenIDs(ctx, []int64{valid, revoked})
	require.Error(t, err)
	assert.Nil(t, invalid)
}
