package verifications

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func TestLookupDoesNotConsumeTheToken(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	svc := NewService(pool, userSvc)
	uid := dbtest.InsertUser(t, pool, "lookup@example.com")
	other := dbtest.InsertUser(t, pool, "lookup-other@example.com")

	raw, err := svc.Issue(ctx, uid)
	require.NoError(t, err)
	otherRaw, err := svc.Issue(ctx, other)
	require.NoError(t, err)

	verified := func(id int64) bool {
		t.Helper()
		u, err := userSvc.FindByID(ctx, id)
		require.NoError(t, err)
		return u.EmailVerifiedAt.Valid
	}

	// Looking at the token, as a mail scanner or a link preview does with a
	// GET, changes nothing — however often it happens.
	for i := 0; i < 3; i++ {
		got, err := svc.Lookup(ctx, raw)
		require.NoError(t, err)
		assert.Equal(t, uid, got)
	}
	assert.False(t, verified(uid), "a lookup must not verify the address")

	// The token is still good for the one call that consumes it.
	got, err := svc.Consume(ctx, raw)
	require.NoError(t, err)
	assert.Equal(t, uid, got)
	assert.True(t, verified(uid))

	// After that it is gone for both calls.
	_, err = svc.Lookup(ctx, raw)
	require.ErrorIs(t, err, ErrInvalidVerification)
	_, err = svc.Consume(ctx, raw)
	require.ErrorIs(t, err, ErrInvalidVerification)

	// Another account's token is untouched.
	got, err = svc.Lookup(ctx, otherRaw)
	require.NoError(t, err)
	assert.Equal(t, other, got)
	assert.False(t, verified(other))

	// Tokens that are no tokens.
	for _, bad := range []string{"", "does-not-exist"} {
		got, err := svc.Lookup(ctx, bad)
		require.ErrorIs(t, err, ErrInvalidVerification, "%q", bad)
		assert.Zero(t, got)
	}

	// An expired token is refused by lookup and by consume.
	const expired = "expired-raw-token"
	sum := sha256.Sum256([]byte(expired))
	require.NoError(t, sqlcgen.New(pool).CreateEmailVerification(ctx, sqlcgen.CreateEmailVerificationParams{
		TokenHash:  sum[:],
		UserID:     other,
		TtlSeconds: -60, // a minute before the database's now
	}))
	_, err = svc.Lookup(ctx, expired)
	require.ErrorIs(t, err, ErrInvalidVerification)
	_, err = svc.Consume(ctx, expired)
	require.ErrorIs(t, err, ErrInvalidVerification)
	assert.False(t, verified(other))
}
