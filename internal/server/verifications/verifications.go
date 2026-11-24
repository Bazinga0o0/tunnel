// Package verifications issues and consumes email-verification tokens.
package verifications

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// ErrInvalidVerification is returned when a token is unknown or expired.
var ErrInvalidVerification = errors.New("invalid or expired verification token")

const (
	// TTL is how long a verification link remains valid.
	TTL = 24 * time.Hour
	// rawBytes of entropy -> base64url -> ~43 chars in the email link.
	rawBytes = 32
)

type Service struct {
	q       *sqlcgen.Queries
	userSvc *users.Service
}

// NewService builds a verifications service. It needs the users service so
// Consume can flip the user's email_verified_at flag atomically (best-effort).
func NewService(pool *pgxpool.Pool, userSvc *users.Service) *Service {
	return &Service{q: sqlcgen.New(pool), userSvc: userSvc}
}

// Issue creates a new verification for userID and returns the raw token
// (base64url-encoded) that should be emailed to the user.
func (s *Service) Issue(ctx context.Context, userID int64) (string, error) {
	buf := make([]byte, rawBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))

	// The database adds TTL to its own clock, the one lookups compare with.
	err := s.q.CreateEmailVerification(ctx, sqlcgen.CreateEmailVerificationParams{
		TokenHash:  sum[:],
		UserID:     userID,
		TtlSeconds: TTL.Seconds(),
	})
	if err != nil {
		return "", err
	}
	return raw, nil
}

// Lookup reports which user a raw token belongs to without using it up:
// nothing is written, the address is not marked verified, and the token
// stays valid for a later Consume. Returns ErrInvalidVerification for an
// empty, unknown, used or expired token.
//
// It exists so that opening the link in the mail (a GET, which mail
// scanners and link previews also send) can show a confirmation page, and
// only the POST from that page calls Consume.
func (s *Service) Lookup(ctx context.Context, raw string) (int64, error) {
	if raw == "" {
		return 0, ErrInvalidVerification
	}
	sum := sha256.Sum256([]byte(raw))
	row, err := s.q.GetEmailVerificationByHash(ctx, sum[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrInvalidVerification
		}
		return 0, err
	}
	return row.UserID, nil
}

// Consume validates the raw token, marks the user's email verified, and
// deletes all verifications for that user. Single-use. To look at a token
// without using it, call Lookup.
func (s *Service) Consume(ctx context.Context, raw string) (int64, error) {
	if raw == "" {
		return 0, ErrInvalidVerification
	}
	sum := sha256.Sum256([]byte(raw))
	row, err := s.q.GetEmailVerificationByHash(ctx, sum[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrInvalidVerification
		}
		return 0, err
	}
	if err := s.userSvc.MarkEmailVerified(ctx, row.UserID); err != nil {
		return 0, err
	}
	if err := s.q.DeleteEmailVerificationsForUser(ctx, row.UserID); err != nil {
		// Best-effort; the verified flag is already set. Not returning the
		// error because the caller's main goal (verified=true) succeeded.
		_ = err
	}
	return row.UserID, nil
}
