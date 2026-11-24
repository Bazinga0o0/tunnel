package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenVerifierAccepts(t *testing.T) {
	v := NewTokenVerifier([]string{"twbl_a", "twbl_b"})
	assert.True(t, v.Verify("twbl_a"))
	assert.True(t, v.Verify("twbl_b"))
}

func TestTokenVerifierRejects(t *testing.T) {
	v := NewTokenVerifier([]string{"twbl_a"})
	assert.False(t, v.Verify("twbl_b"))
	assert.False(t, v.Verify(""))
	assert.False(t, v.Verify("TWBL_A"))
}

func TestTokenVerifierConstantTime(t *testing.T) {
	v := NewTokenVerifier([]string{"twbl_correct"})
	assert.False(t, v.Verify("x"))
	assert.False(t, v.Verify("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))
}

func TestNewStaticTokenVerifierAcceptsTokensOfSixteenCharacters(t *testing.T) {
	const sixteen = "twbl_0123456789a" // exactly 16
	require.Len(t, sixteen, 16)
	const long = "twbl_0123456789abcdefghijklmnopqrstuv"

	v, err := NewStaticTokenVerifier([]string{sixteen, long})
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.True(t, v.Verify(sixteen))
	assert.True(t, v.Verify(long))
	assert.False(t, v.Verify("twbl_0123456789b"))
	assert.False(t, v.Verify(""))
}

func TestNewStaticTokenVerifierRejectsShortTokens(t *testing.T) {
	const fifteen = "twbl_0123456789" // one short
	require.Len(t, fifteen, 15)
	const good = "twbl_0123456789abcdef"

	cases := map[string][]string{
		"fifteen characters":         {fifteen},
		"short after a good one":     {good, fifteen},
		"short before a good one":    {fifteen, good},
		"empty string":               {good, ""},
		"historic test token":        {"twbl_ok"},
		"sixteen bytes, eight runes": {"äöüäöüäö"},
	}
	for name, tokens := range cases {
		t.Run(name, func(t *testing.T) {
			v, err := NewStaticTokenVerifier(tokens)
			require.ErrorIs(t, err, ErrStaticTokenTooShort)
			assert.Nil(t, v, "no verifier may be handed out when a token is rejected")
			for _, tok := range tokens {
				if tok != "" {
					assert.NotContains(t, err.Error(), tok, "the error must not echo a secret")
				}
			}
		})
	}
}

func TestNewStaticTokenVerifierWithoutTokensAcceptsNothing(t *testing.T) {
	v, err := NewStaticTokenVerifier(nil)
	require.NoError(t, err)
	assert.False(t, v.Verify(""))
	assert.False(t, v.Verify("twbl_0123456789abcdef"))
}

func TestMinStaticTokenLengthIsSixteen(t *testing.T) {
	assert.Equal(t, 16, MinStaticTokenLength)
}
