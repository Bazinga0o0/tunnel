package acceptor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// tokenID returns the ID of the only active token of the user.
func (f *dbFixture) tokenID(t *testing.T, userID int64) int64 {
	t.Helper()
	rows, err := f.tokens.ListActiveByUser(context.Background(), userID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	return rows[0].ID
}

// KillByToken can only select sessions that know their token: the acceptor
// has to take the token ID from the verifier.
func TestKillByTokenEndsOnlyTheSessionsOfThatToken(t *testing.T) {
	fx := newDBFixture(t)
	uid, raw := fx.user(t, "two-laptops@example.com")
	firstToken := fx.tokenID(t, uid)
	secondRaw, _, err := fx.tokens.Issue(context.Background(), uid, "second laptop")
	require.NoError(t, err)

	reg := registry.New()
	opts := fx.dbOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)

	revoked1, _ := login(t, addr, raw)
	revoked2, _ := login(t, addr, raw)
	require.Empty(t, revoked2.registerHTTP("revoked").Error)
	other, _ := login(t, addr, secondRaw)

	assert.Equal(t, 2, reg.KillByToken(firstToken))

	revoked1.requireClosed(waitFor)
	revoked2.requireClosed(waitFor)
	other.requireOpen()
}

func TestHelloAckCarriesTheConfiguredServerVersion(t *testing.T) {
	opts := staticOpts()
	opts.ServerVersion = "1.2.3-test"
	addr, _ := serve(t, opts, nil)
	_, ack := login(t, addr, staticToken)
	assert.Equal(t, "1.2.3-test", ack.ServerVersion)
}

func TestHelloAckWithoutAConfiguredVersionNamesNone(t *testing.T) {
	addr, _ := serve(t, staticOpts(), nil)
	_, ack := login(t, addr, staticToken)
	assert.Empty(t, ack.ServerVersion, "no made-up version")
}
