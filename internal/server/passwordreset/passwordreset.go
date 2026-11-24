// Package passwordreset issues and consumes password-reset tokens.
package passwordreset

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
	"github.com/Bazinga0o0/tunnel/internal/server/sessions"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// ErrInvalidReset is returned when a token is unknown or expired.
var ErrInvalidReset = errors.New("invalid or expired reset token")

const (
	// TTL is how long a reset link remains valid.
	TTL = 1 * time.Hour
	// rawBytes of entropy.
	rawBytes = 32
)

type Service struct {
	pool    *pgxpool.Pool
	q       *sqlcgen.Queries
	userSvc *users.Service

	// hash is the password KDF. It is a field so that tests can count the
	// calls; production code never changes it.
	hash func(ctx context.Context, password string) (string, error)
}

// NewService builds a password-reset service. It uses users to find the
// account for an address and for the password rules. The sessions service
// is no longer used: Consume deletes the sessions itself, inside its
// transaction. The parameter remains so that existing callers compile.
func NewService(pool *pgxpool.Pool, userSvc *users.Service, _ *sessions.Service) *Service {
	return &Service{pool: pool, q: sqlcgen.New(pool), userSvc: userSvc, hash: auth.HashPasswordContext}
}

// Issue creates a reset token for the user with the given email. If no user
// matches, Issue returns ("", 0, nil) — callers must treat the email as
// "maybe unknown" and NOT distinguish in user-facing responses (no account
// enumeration).
//
// Deprecated: Issue does not say where the mail has to go, which invites
// sending it to the address the client typed. Use IssueWithAddress.
func (s *Service) Issue(ctx context.Context, email string) (string, int64, error) {
	raw, userID, _, err := s.IssueWithAddress(ctx, email)
	return raw, userID, err
}

// IssueWithAddress creates a reset token for the account with the given
// email address and returns the raw token, the account's id and the address
// stored for the account.
//
// The mail with the token must go to storedEmail and to no other address —
// never to the email argument. The account is found by a case-insensitive
// comparison in the database, so the address a client typed can match an
// account without being the same address; mailing the typed spelling would
// hand the token to whoever receives mail for it.
//
// If no account matches, or the account is disabled, it returns
// ("", 0, "", nil) and has written nothing. Callers must answer the client
// the same way in all these cases (no account enumeration).
func (s *Service) IssueWithAddress(ctx context.Context, email string) (raw string, userID int64, storedEmail string, err error) {
	u, err := s.userSvc.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			return "", 0, "", nil
		}
		return "", 0, "", err
	}
	// A disabled account gets no reset link. The answer, and the work done
	// for it (the one lookup above), are those for an unknown address.
	if u.DisabledAt.Valid {
		return "", 0, "", nil
	}

	buf := make([]byte, rawBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", 0, "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))

	// The database adds TTL to its own clock, the one Consume compares with.
	err = s.q.CreatePasswordReset(ctx, sqlcgen.CreatePasswordResetParams{
		TokenHash:  sum[:],
		UserID:     u.ID,
		TtlSeconds: TTL.Seconds(),
	})
	if err != nil {
		return "", 0, "", err
	}
	return raw, u.ID, u.Email, nil
}

// Consume uses the token up, sets the new password, deletes all sessions of
// the user and all their other reset tokens, and returns the user's id.
//
// All of that is one transaction. It locks the account row and then deletes
// the token row with DELETE … RETURNING: of two calls with the same token
// exactly one gets the row, the other returns ErrInvalidReset. When any
// later step fails the transaction is rolled back: the password is
// unchanged and the token is still valid.
//
// The account row is locked before the token row because users.Disable,
// users.SetPassword and users.ChangePassword take them in that order too
// (account, then reset tokens). With one order for all, none of them can
// deadlock with another on the same account.
//
// Errors: ErrInvalidReset for an empty, unknown, used or expired token and
// for a token of a disabled account; users.ErrPasswordTooShort /
// users.ErrPasswordTooLong for the password; auth.ErrBusy (wrapped) when
// the password hash could not start in time. A rejected password does not
// use the token up.
func (s *Service) Consume(ctx context.Context, raw, newPassword string) (int64, error) {
	if raw == "" {
		return 0, ErrInvalidReset
	}
	if err := s.userSvc.ValidatePassword(newPassword); err != nil {
		return 0, err
	}
	sum := sha256.Sum256([]byte(raw))

	// A look at the token before the hash, so that a request with a made-up
	// token, or one of a disabled account, does not cost 64 MiB of argon2.
	// It tells which account to lock and decides nothing else: the account
	// is checked and the token taken inside the transaction below.
	pending, err := s.q.GetPasswordResetByHash(ctx, sum[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrInvalidReset
		}
		return 0, fmt.Errorf("look up reset token: %w", err)
	}

	// Hash before the transaction opens: no connection and no row lock is
	// held while the KDF runs or waits for a slot.
	hash, err := s.hash(ctx, newPassword)
	if err != nil {
		return 0, fmt.Errorf("hash password: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)

	account, err := q.GetUserByIDForUpdate(ctx, pending.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrInvalidReset
		}
		return 0, fmt.Errorf("lock account: %w", err)
	}
	if account.DisabledAt.Valid {
		return 0, ErrInvalidReset
	}
	userID, err := q.TakePasswordReset(ctx, sum[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrInvalidReset
		}
		return 0, fmt.Errorf("take reset token: %w", err)
	}
	if _, err := q.UpdateUserPassword(ctx, sqlcgen.UpdateUserPasswordParams{ID: userID, PasswordHash: hash}); err != nil {
		return 0, fmt.Errorf("update password: %w", err)
	}
	// Browsers that were logged in with the old password are logged out.
	if err := q.DeleteSessionsByUser(ctx, userID); err != nil {
		return 0, fmt.Errorf("delete sessions: %w", err)
	}
	// Other links that are still open for this user stop working too.
	if err := q.DeletePasswordResetsForUser(ctx, userID); err != nil {
		return 0, fmt.Errorf("delete open resets: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return userID, nil
}
