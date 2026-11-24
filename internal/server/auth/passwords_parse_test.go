package auth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

// encodeTestHash builds a syntactically complete hash string from raw parts
// so each test case can bend exactly one field.
func encodeTestHash(version int, params string, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$%s$%s$%s",
		version, params,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func TestVerifyRejectsOutOfBoundsHashWithoutPanic(t *testing.T) {
	salt := make([]byte, 16)
	key := make([]byte, 32)
	const okParams = "m=65536,t=3,p=4"

	cases := map[string]string{
		"version 16 (argon2 1.0)":   encodeTestHash(0x10, okParams, salt, key),
		"version 0":                 encodeTestHash(0, okParams, salt, key),
		"version with trailer":      strings.Replace(encodeTestHash(argon2.Version, okParams, salt, key), "v=19", "v=19x", 1),
		"iterations zero":           encodeTestHash(argon2.Version, "m=65536,t=0,p=4", salt, key),
		"iterations above bound":    encodeTestHash(argon2.Version, "m=65536,t=17,p=4", salt, key),
		"parallelism zero":          encodeTestHash(argon2.Version, "m=65536,t=3,p=0", salt, key),
		"parallelism above bound":   encodeTestHash(argon2.Version, "m=65536,t=3,p=17", salt, key),
		"parallelism wraps uint8":   encodeTestHash(argon2.Version, "m=65536,t=3,p=260", salt, key),
		"memory zero":               encodeTestHash(argon2.Version, "m=0,t=3,p=4", salt, key),
		"memory below 8 per lane":   encodeTestHash(argon2.Version, "m=31,t=3,p=4", salt, key),
		"memory above bound":        encodeTestHash(argon2.Version, "m=262145,t=3,p=4", salt, key),
		"memory 4 TiB":              encodeTestHash(argon2.Version, "m=4294967295,t=3,p=4", salt, key),
		"memory overflows uint32":   encodeTestHash(argon2.Version, "m=4294967296,t=3,p=4", salt, key),
		"negative parameter":        encodeTestHash(argon2.Version, "m=65536,t=-3,p=4", salt, key),
		"parameters reordered":      encodeTestHash(argon2.Version, "t=3,m=65536,p=4", salt, key),
		"parameter missing":         encodeTestHash(argon2.Version, "m=65536,t=3", salt, key),
		"parameter trailer":         encodeTestHash(argon2.Version, "m=65536,t=3,p=4,x=1", salt, key),
		"parameter with space":      encodeTestHash(argon2.Version, "m=65536,t=3,p= 4", salt, key),
		"parameter with plus sign":  encodeTestHash(argon2.Version, "m=65536,t=+3,p=4", salt, key),
		"parameter in hex":          encodeTestHash(argon2.Version, "m=0x10000,t=3,p=4", salt, key),
		"parameter with underscore": encodeTestHash(argon2.Version, "m=65_536,t=3,p=4", salt, key),
		"full-width digits":         encodeTestHash(argon2.Version, "m=65536,t=３,p=4", salt, key),
		"empty parameter value":     encodeTestHash(argon2.Version, "m=65536,t=,p=4", salt, key),
		"empty key":                 encodeTestHash(argon2.Version, okParams, salt, nil),
		"key too short":             encodeTestHash(argon2.Version, okParams, salt, make([]byte, 15)),
		"key too long":              encodeTestHash(argon2.Version, okParams, salt, make([]byte, 65)),
		"empty salt":                encodeTestHash(argon2.Version, okParams, nil, key),
		"salt too short":            encodeTestHash(argon2.Version, okParams, make([]byte, 7), key),
		"salt too long":             encodeTestHash(argon2.Version, okParams, make([]byte, 65), key),
		"salt not base64":           "$argon2id$v=19$" + okParams + "$!!!!$" + base64.RawStdEncoding.EncodeToString(key),
		"wrong algorithm":           strings.Replace(encodeTestHash(argon2.Version, okParams, salt, key), "argon2id", "argon2i", 1),
		"too few fields":            "$argon2id$v=19$" + okParams,
		"too many fields":           encodeTestHash(argon2.Version, okParams, salt, key) + "$extra",
		"empty string":              "",
		"oversized string":          encodeTestHash(argon2.Version, okParams, salt, key) + strings.Repeat("A", 600),
		"only separators":           "$$$$$",
		"missing leading separator": strings.TrimPrefix(encodeTestHash(argon2.Version, okParams, salt, key), "$"),
	}

	for name, stored := range cases {
		t.Run(name, func(t *testing.T) {
			// The parser must reject the hash before the KDF is reached: a KDF
			// call with these values either panics or allocates without bound.
			restore := stubKDF(func(_, _ []byte, _, _ uint32, _ uint8, _ uint32) []byte {
				t.Fatalf("KDF must not run for a rejected hash")
				return nil
			})
			defer restore()

			var ok bool
			var err error
			require.NotPanics(t, func() { ok, err = VerifyPassword(stored, "whatever") })
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrMalformedHash)
			assert.False(t, ok)
		})
	}
}

func TestVerifyAcceptsHashAtTheBounds(t *testing.T) {
	// Smallest and largest parameter sets the parser lets through. The KDF is
	// stubbed: the point is that the parser hands exactly these values on.
	type seen struct {
		time, memory uint32
		threads      uint8
		keyLen       uint32
	}
	var got seen
	restore := stubKDF(func(_, _ []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
		got = seen{time, memory, threads, keyLen}
		return make([]byte, keyLen)
	})
	defer restore()

	ok, err := VerifyPassword(encodeTestHash(argon2.Version, "m=8,t=1,p=1", make([]byte, 8), make([]byte, 16)), "pw")
	require.NoError(t, err)
	assert.True(t, ok, "stub returns an all-zero key, the stored key is all zero")
	assert.Equal(t, seen{time: 1, memory: 8, threads: 1, keyLen: 16}, got)

	ok, err = VerifyPassword(encodeTestHash(argon2.Version, "m=262144,t=16,p=16", make([]byte, 64), make([]byte, 64)), "pw")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, seen{time: 16, memory: 262144, threads: 16, keyLen: 64}, got)
}

func TestVerifyRejectsHashWithRealKDFParametersThatUsedToPanic(t *testing.T) {
	// No stub here: with the real argon2 implementation t=0 and p=0 panic
	// inside the library. The parser has to stop them.
	salt := make([]byte, 16)
	key := make([]byte, 32)
	for _, params := range []string{"m=65536,t=0,p=4", "m=65536,t=3,p=0"} {
		require.NotPanics(t, func() {
			_, err := VerifyPassword(encodeTestHash(argon2.Version, params, salt, key), "pw")
			require.ErrorIs(t, err, ErrMalformedHash)
		}, params)
	}
}

func TestParserErrorDoesNotQuoteTheHash(t *testing.T) {
	// The error ends up in logs. It may say what is wrong, not repeat the
	// salt or the key.
	salt := []byte("0123456789abcdef")
	key := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	keyB64 := base64.RawStdEncoding.EncodeToString(key)

	for _, stored := range []string{
		encodeTestHash(argon2.Version, "m=65536,t=0,p=4", salt, key),
		encodeTestHash(0x10, "m=65536,t=3,p=4", salt, key),
		encodeTestHash(argon2.Version, "m=65536,t=3,p=4", salt, key) + "$extra",
		encodeTestHash(argon2.Version, "m=65536,t=3,p=4", salt, append(key, make([]byte, 40)...)),
	} {
		_, err := VerifyPassword(stored, "pw")
		require.ErrorIs(t, err, ErrMalformedHash)
		assert.NotContains(t, err.Error(), saltB64)
		assert.NotContains(t, err.Error(), keyB64)
		assert.NotContains(t, err.Error(), stored)
	}
}

func TestHashPasswordOutputPassesTheParser(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	require.NoError(t, err)
	p, err := parseHash(hash)
	require.NoError(t, err)
	assert.EqualValues(t, argonMemoryKB, p.memoryKB)
	assert.EqualValues(t, argonIterations, p.iterations)
	assert.EqualValues(t, argonParallel, p.parallelism)
	assert.Len(t, p.salt, argonSaltBytes)
	assert.Len(t, p.key, argonKeyBytes)
}
