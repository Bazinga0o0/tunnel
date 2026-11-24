package auth

import (
	"context"

	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
)

// DBVerifier checks tunnel-client tokens against the database.
// Replaces the static TokenVerifier once a Postgres DB is configured.
type DBVerifier struct {
	svc *tokens.Service
}

// NewDBVerifier wraps a tokens.Service for verification use.
func NewDBVerifier(svc *tokens.Service) *DBVerifier {
	return &DBVerifier{svc: svc}
}

// VerifyWithUser returns the owning user_id if the token is valid,
// or (0, false) otherwise. See VerifyWithToken.
func (v *DBVerifier) VerifyWithUser(ctx context.Context, raw string) (int64, bool) {
	userID, _, ok := v.VerifyWithToken(ctx, raw)
	return userID, ok
}

// VerifyWithToken returns the owning user's id and the token's id if the
// token is valid, or (0, 0, false) otherwise. Not valid are: an empty or
// unknown token, a revoked or expired one, and a token whose owner is
// disabled. A database error fails closed: it is a refusal as well.
//
// The token id lets the caller attach it to the tunnel session, so that
// revoking the token can close the sessions that were opened with it.
func (v *DBVerifier) VerifyWithToken(ctx context.Context, raw string) (userID int64, tokenID int64, ok bool) {
	if raw == "" {
		return 0, 0, false
	}
	userID, tokenID, err := v.svc.VerifyWithID(ctx, raw)
	if err != nil {
		return 0, 0, false
	}
	return userID, tokenID, true
}
