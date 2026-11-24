package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	require.NoError(t, err)
	require.NotEmpty(t, hash)
	assert.Contains(t, hash, "$argon2id$")

	ok, err := VerifyPassword(hash, "correct horse battery staple")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = VerifyPassword(hash, "wrong password")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyRejectsMalformedHash(t *testing.T) {
	_, err := VerifyPassword("not-a-hash", "whatever")
	require.Error(t, err)
}

func TestHashProducesDistinctOutputsForSameInput(t *testing.T) {
	h1, err := HashPassword("same")
	require.NoError(t, err)
	h2, err := HashPassword("same")
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "random salt should make hashes unequal")
}

// The cheap KDF for tests of other packages: hashes keep the form and the
// parameters HashPassword writes, their key is derived at the lowest cost,
// they verify while the cheap KDF is in use, and once restore has put the
// real KDF back they no longer do.
func TestUseCheapKDFForTesting(t *testing.T) {
	restore := UseCheapKDFForTesting()
	restored := false
	defer func() {
		if !restored {
			restore()
		}
	}()
	stored, err := HashPassword("correct horse battery staple")
	require.NoError(t, err)
	p, err := parseHash(stored)
	require.NoError(t, err)
	assert.Equal(t, hashParams{memoryKB: argonMemoryKB, iterations: argonIterations, parallelism: argonParallel, salt: p.salt, key: p.key}, p,
		"the parameters of a real hash")
	assert.Equal(t, argon2.IDKey([]byte("correct horse battery staple"), p.salt, 1, 8*argonParallel, argonParallel, argonKeyBytes), p.key,
		"the key at the lowest cost")

	ok, err := VerifyPassword(stored, "correct horse battery staple")
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = VerifyPassword(stored, "wrong password")
	require.NoError(t, err)
	assert.False(t, ok)

	restore()
	restored = true
	ok, err = VerifyPassword(stored, "correct horse battery staple")
	require.NoError(t, err)
	assert.False(t, ok, "the real KDF is back")
}
