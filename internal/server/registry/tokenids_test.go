package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenIDsListsEachTokenOfTheTrackedSessionsOnce(t *testing.T) {
	r := New()
	assert.Empty(t, r.TokenIDs())

	require.NoError(t, r.AddSession(sess("a", 1, 7), SessionLimits{}))
	require.NoError(t, r.AddSession(sess("b", 1, 7), SessionLimits{})) // same token, two laptops
	require.NoError(t, r.AddSession(sess("c", 2, 5), SessionLimits{}))
	require.NoError(t, r.AddSession(sess("static", 0, 0), SessionLimits{}))
	// A session that entered through a registration counts as well.
	require.NoError(t, r.RegisterHTTP("myapp", sess("d", 3, 9)))

	assert.Equal(t, []int64{5, 7, 9}, r.TokenIDs(), "sorted, without duplicates and without the static session")

	r.KillByToken(7)
	assert.Equal(t, []int64{5, 9}, r.TokenIDs())
	r.Unregister(sess("d", 3, 9))
	assert.Equal(t, []int64{5}, r.TokenIDs())
}
