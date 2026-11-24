// Package tokens issues and verifies API tokens used by the CLI client.
package tokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
)

const (
	TokenPrefix   = "twbl_"
	tokenBodyLen  = 32 // chars after prefix
	prefixDisplay = 8  // chars kept for UI after prefix
)

// Defaults for Options.
const (
	DefaultMaxActivePerUser = 25
	DefaultMaxNameLength    = 64
)

var (
	// ErrInvalidToken is returned for a token that cannot be used: unknown,
	// revoked, expired, owned by a disabled account or, with
	// Options.RequireApproved, by an account that is not approved. Callers
	// get the same error for all of them.
	ErrInvalidToken = errors.New("invalid or revoked token")

	// ErrTooManyTokens is returned by Issue when the user already has
	// Options.MaxActivePerUser active tokens.
	ErrTooManyTokens = errors.New("too many active tokens")

	// ErrNameTooLong is returned by Issue when the token name has more than
	// Options.MaxNameLength characters.
	ErrNameTooLong = errors.New("token name is too long")
)

// alphabet is URL-safe base62.
const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Options sets the per-user limits of the service and whether a token's
// owner must be approved.
//
// Convention for every limit: zero selects the default, a negative value
// switches the limit off.
type Options struct {
	// MaxActivePerUser is the number of active tokens (not revoked, not
	// expired) one user may hold. Zero selects DefaultMaxActivePerUser (25);
	// a negative value removes the limit.
	MaxActivePerUser int
	// MaxNameLength is the longest token name Issue accepts, in characters.
	// Zero selects DefaultMaxNameLength (64); a negative value removes the
	// limit.
	MaxNameLength int
	// RequireApproved makes a token usable only while an admin has approved
	// its owner (users.approved_at set): VerifyWithID refuses the others and
	// InvalidTokenIDs reports them. The server sets it when auth.signup is
	// "approval" or "closed". False, the default, ignores approval.
	RequireApproved bool
}

type Service struct {
	pool             *pgxpool.Pool
	q                *sqlcgen.Queries
	maxActivePerUser int // <= 0: unlimited
	maxNameLength    int // <= 0: unlimited
	requireApproved  bool
}

// NewService builds the service with the default limits.
func NewService(pool *pgxpool.Pool) *Service {
	return NewServiceWithOptions(pool, Options{})
}

// NewServiceWithOptions builds the service with the given limits.
func NewServiceWithOptions(pool *pgxpool.Pool, opts Options) *Service {
	if opts.MaxActivePerUser == 0 {
		opts.MaxActivePerUser = DefaultMaxActivePerUser
	}
	if opts.MaxNameLength == 0 {
		opts.MaxNameLength = DefaultMaxNameLength
	}
	return &Service{
		pool:             pool,
		q:                sqlcgen.New(pool),
		maxActivePerUser: opts.MaxActivePerUser,
		maxNameLength:    opts.MaxNameLength,
		requireApproved:  opts.RequireApproved,
	}
}

// Issue creates a new token for userID. Returns the raw token string (only
// chance to see it — only the sha256 hash persists) plus the stored row.
//
// Returns ErrNameTooLong for a name over the length limit and
// ErrTooManyTokens when the user is at the limit of active tokens. The
// count and the insert run in one transaction that locks the user row, so
// concurrent calls cannot exceed the limit together.
func (s *Service) Issue(ctx context.Context, userID int64, name string) (string, *sqlcgen.ApiToken, error) {
	if s.maxNameLength > 0 && utf8.RuneCountInString(name) > s.maxNameLength {
		return "", nil, ErrNameTooLong
	}

	raw, err := generateTokenString()
	if err != nil {
		return "", nil, fmt.Errorf("generate: %w", err)
	}
	hash := sha256.Sum256([]byte(raw))
	displayPrefix := raw[len(TokenPrefix) : len(TokenPrefix)+prefixDisplay]

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)

	if s.maxActivePerUser > 0 {
		if _, err := q.LockUserForChildInsert(ctx, userID); err != nil {
			return "", nil, fmt.Errorf("lock user %d: %w", userID, err)
		}
		active, err := q.CountActiveTokensByUser(ctx, userID)
		if err != nil {
			return "", nil, fmt.Errorf("count active tokens: %w", err)
		}
		if active >= int64(s.maxActivePerUser) {
			return "", nil, ErrTooManyTokens
		}
	}

	row, err := q.CreateAPIToken(ctx, sqlcgen.CreateAPITokenParams{
		UserID:      userID,
		Name:        name,
		TokenHash:   hash[:],
		TokenPrefix: displayPrefix,
	})
	if err != nil {
		return "", nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", nil, fmt.Errorf("commit: %w", err)
	}
	return raw, &row, nil
}

// Verify looks up a raw token and returns the owning user_id if valid.
// See VerifyWithID for what valid means.
func (s *Service) Verify(ctx context.Context, raw string) (int64, error) {
	userID, _, err := s.VerifyWithID(ctx, raw)
	return userID, err
}

// VerifyWithID looks up a raw token and returns the owning user's id and
// the token's id. A token is valid while it is not revoked, not expired and
// its owner is not disabled and, with Options.RequireApproved, approved;
// anything else is ErrInvalidToken.
func (s *Service) VerifyWithID(ctx context.Context, raw string) (userID, tokenID int64, err error) {
	if raw == "" {
		return 0, 0, ErrInvalidToken
	}
	hash := sha256.Sum256([]byte(raw))
	row, err := s.q.GetAPITokenByHash(ctx, sqlcgen.GetAPITokenByHashParams{
		TokenHash:       hash[:],
		RequireApproved: s.requireApproved,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, ErrInvalidToken
		}
		return 0, 0, err
	}
	// Opportunistic last-used-at update; ignore errors.
	_ = s.q.TouchAPITokenUsage(ctx, row.ID)
	return row.UserID, row.ID, nil
}

// InvalidTokenIDs returns those of ids that can no longer be used: revoked,
// expired, deleted (or never existing), owned by a disabled account or, with
// Options.RequireApproved, by an account that is not approved. The result
// keeps the order of ids, without duplicates. It costs one query.
//
// An error says nothing about the tokens: the caller must not treat any of
// them as invalid then.
func (s *Service) InvalidTokenIDs(ctx context.Context, ids []int64) ([]int64, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	usableIDs, err := s.q.ListUsableAPITokenIDs(ctx, sqlcgen.ListUsableAPITokenIDsParams{
		Ids:             ids,
		RequireApproved: s.requireApproved,
	})
	if err != nil {
		return nil, err
	}
	usable := make(map[int64]bool, len(usableIDs))
	for _, id := range usableIDs {
		usable[id] = true
	}
	var invalid []int64
	seen := make(map[int64]bool, len(ids))
	for _, id := range ids {
		if seen[id] || usable[id] {
			continue
		}
		seen[id] = true
		invalid = append(invalid, id)
	}
	return invalid, nil
}

// CountActiveByUserQuery returns the number of active tokens (not revoked,
// not expired) for userID (used by admin detail page).
func (s *Service) CountActiveByUserQuery(ctx context.Context, userID int64) (int64, error) {
	return s.q.CountActiveTokensByUser(ctx, userID)
}

// CountActiveByUser returns the number of active tokens (not revoked, not
// expired) for userID.
func (s *Service) CountActiveByUser(ctx context.Context, userID int64) (int, error) {
	n, err := s.q.CountActiveTokensByUser(ctx, userID)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// RevokeForUser revokes token tokenID if it belongs to userID and is not
// revoked yet, and reports whether a row changed. False without an error
// means: no such token, somebody else's token, or already revoked — the
// caller cannot and need not tell these apart.
//
// This is the method for a user acting on their own tokens.
func (s *Service) RevokeForUser(ctx context.Context, userID, tokenID int64) (bool, error) {
	n, err := s.q.RevokeAPITokenForUser(ctx, sqlcgen.RevokeAPITokenForUserParams{
		ID:     tokenID,
		UserID: userID,
	})
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// RevokeAny revokes token tokenID whoever owns it and reports whether a row
// changed (false: no such token or already revoked). It is the admin
// variant; code acting for an ordinary user must call RevokeForUser.
func (s *Service) RevokeAny(ctx context.Context, tokenID int64) (bool, error) {
	n, err := s.q.RevokeAPIToken(ctx, tokenID)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Revoke marks a token as revoked whoever owns it.
//
// Deprecated: it neither checks the owner nor reports whether anything
// changed. Use RevokeForUser for a user's own tokens and RevokeAny for
// admin actions.
func (s *Service) Revoke(ctx context.Context, tokenID int64) error {
	_, err := s.RevokeAny(ctx, tokenID)
	return err
}

// FindByID returns the token row with the given ID, including revoked ones.
// This is primarily used by the frontend to check ownership before revoking.
func (s *Service) FindByID(ctx context.Context, id int64) (*sqlcgen.ApiToken, error) {
	row, err := s.q.GetAPITokenByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	return &row, nil
}

// ListActiveByUser returns the user's non-revoked tokens, newest first.
// Expired tokens are included so that the owner can see and revoke them;
// their ExpiresAt tells them apart.
func (s *Service) ListActiveByUser(ctx context.Context, userID int64) ([]sqlcgen.ListAPITokensByUserRow, error) {
	rows, err := s.q.ListAPITokensByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]sqlcgen.ListAPITokensByUserRow, 0, len(rows))
	for _, r := range rows {
		if !r.RevokedAt.Valid {
			out = append(out, r)
		}
	}
	return out, nil
}

// generateTokenString returns "twbl_" + 32 base62 chars using unbiased sampling.
func generateTokenString() (string, error) {
	out := make([]byte, 0, tokenBodyLen)
	n := big.NewInt(int64(len(alphabet)))
	for i := 0; i < tokenBodyLen; i++ {
		idx, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", err
		}
		out = append(out, alphabet[idx.Int64()])
	}
	return TokenPrefix + string(out), nil
}
