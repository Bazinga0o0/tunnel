// Package auth handles authentication of incoming tunnel clients.
package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"unicode/utf8"
)

// MinStaticTokenLength is the shortest static token NewStaticTokenVerifier
// accepts, in characters.
const MinStaticTokenLength = 16

// ErrStaticTokenTooShort is returned by NewStaticTokenVerifier when a
// configured token has fewer than MinStaticTokenLength characters.
var ErrStaticTokenTooShort = errors.New("auth: static token is too short")

// TokenVerifier checks tunnel-client tokens against a static allow-list.
type TokenVerifier struct {
	tokens [][]byte
}

// NewStaticTokenVerifier builds a verifier from the configured tokens and
// refuses the whole list when one of them is shorter than
// MinStaticTokenLength characters (an empty string included). The error
// wraps ErrStaticTokenTooShort and names the position of the token, never
// its value.
//
// This is the constructor for tokens that come from configuration.
func NewStaticTokenVerifier(tokens []string) (*TokenVerifier, error) {
	converted := make([][]byte, 0, len(tokens))
	for i, t := range tokens {
		if utf8.RuneCountInString(t) < MinStaticTokenLength {
			return nil, fmt.Errorf("%w: token %d of %d has fewer than %d characters",
				ErrStaticTokenTooShort, i+1, len(tokens), MinStaticTokenLength)
		}
		converted = append(converted, []byte(t))
	}
	return &TokenVerifier{tokens: converted}, nil
}

// NewTokenVerifier builds a verifier from the given tokens without a length
// check; empty strings are skipped.
//
// Deprecated: it accepts tokens of any length. Use NewStaticTokenVerifier
// for tokens that come from configuration. This constructor remains for
// existing callers and tests that use short fixture tokens.
func NewTokenVerifier(tokens []string) *TokenVerifier {
	converted := make([][]byte, 0, len(tokens))
	for _, t := range tokens {
		if t == "" {
			continue
		}
		converted = append(converted, []byte(t))
	}
	return &TokenVerifier{tokens: converted}
}

// Verify checks the input against all configured tokens using constant-time compare.
func (v *TokenVerifier) Verify(candidate string) bool {
	c := []byte(candidate)
	for _, t := range v.tokens {
		if subtle.ConstantTimeCompare(c, t) == 1 {
			return true
		}
	}
	return false
}
