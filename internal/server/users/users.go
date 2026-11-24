// Package users provides the user creation/lookup service backed by Postgres.
package users

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
)

// Defaults for the password rules in Options. The rules are enforced at the
// service layer so callers can't bypass them; frontend handlers may call
// Service.ValidatePassword and ValidateEmail first for nicer error pages.
const (
	// MinPasswordLength is the default minimum length of a password a user
	// chooses, in characters (runes, not bytes).
	MinPasswordLength = 8
	// MinAdminPasswordLength is the default minimum length of a password an
	// admin sets for an account (SetPassword), in characters.
	MinAdminPasswordLength = 12
	// MaxPasswordBytes is the default maximum length of any password, in
	// bytes.
	MaxPasswordBytes = 1024
)

// MaxEmailBytes is the maximum length of an email address, in bytes. It is
// part of what an address is, not a setting.
const MaxEmailBytes = 254

var (
	ErrEmailTaken = errors.New("email already registered")
	ErrNotFound   = errors.New("user not found")

	// ErrPasswordTooShort and ErrPasswordTooLong are returned wrapped, with
	// the rule that was broken in the text ("password is too short: must be
	// at least 8 characters"). The text names no secret and can be shown to
	// the user.
	ErrPasswordTooShort = errors.New("password is too short")
	ErrPasswordTooLong  = errors.New("password is too long")

	// ErrInvalidEmail is returned by Create and ValidateEmail for anything
	// that is not a bare email address.
	ErrInvalidEmail = errors.New("invalid email address")

	// ErrLastAdmin is returned by Demote and Disable when the change would
	// leave the system without an active (not disabled) admin.
	ErrLastAdmin = errors.New("would leave no active admin")

	// ErrInvalidCredentials is returned by Authenticate when the address is
	// unknown or the password is wrong. The two cases are deliberately one
	// error.
	ErrInvalidCredentials = errors.New("invalid email or password")

	// ErrAccountDisabled is returned by Authenticate when the password is
	// right but the account is disabled. Show the client the same message as
	// for ErrInvalidCredentials; the distinction is for logs and the audit
	// trail.
	ErrAccountDisabled = errors.New("account is disabled")

	// ErrNotPending is returned by DeletePending when the account does not
	// exist, is approved, is an admin, is disabled or is in use (holds an API
	// token or a reservation).
	ErrNotPending = errors.New("account does not wait for approval")
)

// SessionPurger is satisfied by sessions.Service. Defined here to avoid an
// import cycle between the users and sessions packages.
//
// Deprecated: Disable deletes the sessions itself, inside its transaction,
// and ignores the purger. The type remains for the signature of Disable.
type SessionPurger interface {
	DeleteAllForUser(ctx context.Context, userID int64) error
}

// Options sets the password rules of the service.
//
// Convention for every field: zero selects the default, a negative value
// switches the rule off.
type Options struct {
	// MinPasswordLength is the minimum length, in characters, of a password
	// a user chooses (Create, ChangePassword, password reset). Zero selects
	// MinPasswordLength (8); a negative value removes the minimum.
	MinPasswordLength int
	// MinAdminPasswordLength is the minimum length, in characters, of a
	// password an admin sets for an account (SetPassword,
	// CreateWithAdminPassword). Zero selects MinAdminPasswordLength (12); a
	// negative value removes the minimum.
	MinAdminPasswordLength int
	// MaxPasswordBytes is the maximum length of any password, in bytes.
	// Longer passwords are rejected when set and never match when checked.
	// Zero selects MaxPasswordBytes (1024); a negative value removes the
	// maximum.
	MaxPasswordBytes int
}

type Service struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries

	minPassword      int // characters; <= 0: no minimum
	minAdminPassword int // characters; <= 0: no minimum
	maxPasswordBytes int // <= 0: no maximum

	// Entry points into the password KDF. They are fields so that tests can
	// count the calls; production code never changes them.
	hash        func(ctx context.Context, password string) (string, error)
	verify      func(ctx context.Context, stored, password string) (bool, error)
	dummyVerify func(ctx context.Context, password string) error

	// logger receives the few things the service reports itself. nil means
	// slog.Default(); tests set it to read the output.
	logger *slog.Logger
}

// NewService builds the service with the default password rules.
func NewService(pool *pgxpool.Pool) *Service {
	return NewServiceWithOptions(pool, Options{})
}

// NewServiceWithOptions builds the service with the given password rules.
func NewServiceWithOptions(pool *pgxpool.Pool, opts Options) *Service {
	if opts.MinPasswordLength == 0 {
		opts.MinPasswordLength = MinPasswordLength
	}
	if opts.MinAdminPasswordLength == 0 {
		opts.MinAdminPasswordLength = MinAdminPasswordLength
	}
	if opts.MaxPasswordBytes == 0 {
		opts.MaxPasswordBytes = MaxPasswordBytes
	}
	return &Service{
		pool:             pool,
		q:                sqlcgen.New(pool),
		minPassword:      opts.MinPasswordLength,
		minAdminPassword: opts.MinAdminPasswordLength,
		maxPasswordBytes: opts.MaxPasswordBytes,
		hash:             auth.HashPasswordContext,
		verify:           auth.VerifyPasswordContext,
		dummyVerify:      auth.DummyVerify,
	}
}

// ValidateEmail reports ErrInvalidEmail unless email is a bare address
// ("user@host", no display name, no angle brackets, no comment, no
// surrounding space) that net/mail parses, is at most MaxEmailBytes long and
// contains no control characters.
func ValidateEmail(email string) error {
	if email == "" || len(email) > MaxEmailBytes || !utf8.ValidString(email) {
		return ErrInvalidEmail
	}
	for _, r := range email {
		if unicode.IsControl(r) {
			return ErrInvalidEmail
		}
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Name != "" || addr.Address != email {
		return ErrInvalidEmail
	}
	return nil
}

// ValidatePassword checks a password a user chooses against the service's
// rules: at least Options.MinPasswordLength characters, at most
// Options.MaxPasswordBytes bytes. It returns an error wrapping
// ErrPasswordTooShort or ErrPasswordTooLong. Length is counted in
// characters (runes), so four umlauts are four, not eight.
func (s *Service) ValidatePassword(password string) error {
	return s.validatePassword(password, s.minPassword)
}

// ValidateAdminPassword checks a password an admin sets for an account: at
// least Options.MinAdminPasswordLength characters, at most
// Options.MaxPasswordBytes bytes. It returns an error wrapping
// ErrPasswordTooShort or ErrPasswordTooLong.
func (s *Service) ValidateAdminPassword(password string) error {
	return s.validatePassword(password, s.minAdminPassword)
}

func (s *Service) validatePassword(password string, minRunes int) error {
	if s.tooLong(password) {
		return fmt.Errorf("%w: must be at most %d bytes", ErrPasswordTooLong, s.maxPasswordBytes)
	}
	if minRunes > 0 && utf8.RuneCountInString(password) < minRunes {
		return fmt.Errorf("%w: must be at least %d characters", ErrPasswordTooShort, minRunes)
	}
	return nil
}

// tooLong reports whether password exceeds the maximum length. Such a
// password cannot have been set, so it is never worth a KDF run.
func (s *Service) tooLong(password string) bool {
	return s.maxPasswordBytes > 0 && len(password) > s.maxPasswordBytes
}

// Create stores a new account. It returns ErrInvalidEmail, an error
// wrapping ErrPasswordTooShort or ErrPasswordTooLong, ErrEmailTaken, or an
// error wrapping auth.ErrBusy when the password hash could not start in
// time.
//
// The address is looked up before the password is hashed, so a signup for a
// taken address costs no hash. The unique constraint still decides when two
// signups for one address race.
//
// Create is for a password the account's owner chose (sign-up): the rule is
// ValidatePassword. For a password somebody else sets, use
// CreateWithAdminPassword.
func (s *Service) Create(ctx context.Context, email, password string) (*sqlcgen.User, error) {
	return s.create(ctx, email, password, s.ValidatePassword)
}

// CreateWithAdminPassword is Create for an account whose password is set by
// an operator or admin instead of its owner, as the admin CLI does. The
// rule for the password is ValidateAdminPassword (at least
// Options.MinAdminPasswordLength characters, 12 by default), the same as in
// SetPassword. Everything else, the errors included, is as in Create.
func (s *Service) CreateWithAdminPassword(ctx context.Context, email, password string) (*sqlcgen.User, error) {
	return s.create(ctx, email, password, s.ValidateAdminPassword)
}

func (s *Service) create(ctx context.Context, email, password string, validatePassword func(string) error) (*sqlcgen.User, error) {
	if err := ValidateEmail(email); err != nil {
		return nil, err
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	if _, err := s.q.GetUserByEmail(ctx, email); err == nil {
		return nil, ErrEmailTaken
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("look up email: %w", err)
	}

	hash, err := s.hash(ctx, password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	u, err := s.q.CreateUser(ctx, sqlcgen.CreateUserParams{Email: email, PasswordHash: hash})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return nil, ErrEmailTaken
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	return &u, nil
}

// Authenticate is the password login. It returns the account when email and
// password match and the account is not disabled.
//
// Errors:
//   - ErrInvalidCredentials: unknown address or wrong password.
//   - ErrAccountDisabled: right password, disabled account.
//   - auth.ErrBusy (wrapped): the password check could not start in time.
//
// For an unknown address it verifies the password against a fixed dummy
// hash, so that an unknown and a known address take the same time and
// count the same against the hash limit. Callers must answer
// ErrInvalidCredentials and ErrAccountDisabled with one and the same
// response.
//
// An account whose stored hash cannot be verified at all (not a hash this
// server accepts) is treated the same way as an unknown address: one dummy
// verification, ErrInvalidCredentials. The service logs the account id, so
// that the operator finds the account; the caller cannot tell it apart.
//
// The account is read again after the password check: the check takes long
// enough for the account to be disabled or its password to be changed in
// between, and the state from before must not be trusted.
func (s *Service) Authenticate(ctx context.Context, email, password string) (*sqlcgen.User, error) {
	// Input that no account can match is refused before any work. The answer
	// does not depend on whether the address exists, so it reveals nothing.
	if email == "" || password == "" || s.tooLong(password) ||
		!utf8.ValidString(email) || strings.ContainsRune(email, 0) {
		return nil, ErrInvalidCredentials
	}

	u, err := s.q.GetUserByEmail(ctx, email)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("look up user: %w", err)
		}
		return nil, s.rejectAfterDummyVerify(ctx, password)
	}

	ok, err := s.verify(ctx, u.PasswordHash, password)
	if errors.Is(err, auth.ErrMalformedHash) {
		// Only the id goes to the log: no address, no hash, no password.
		s.log().Warn("users: stored password hash cannot be verified, login refused", "user_id", u.ID)
		return nil, s.rejectAfterDummyVerify(ctx, password)
	}
	if err != nil {
		return nil, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return nil, ErrInvalidCredentials
	}

	fresh, err := s.q.GetUserByID(ctx, u.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("re-read user: %w", err)
	}
	if fresh.PasswordHash != u.PasswordHash {
		return nil, ErrInvalidCredentials
	}
	if fresh.DisabledAt.Valid {
		return nil, ErrAccountDisabled
	}
	return &fresh, nil
}

// rejectAfterDummyVerify is the answer of Authenticate when there is no
// stored hash to check the password against: it does the work of one
// verification and returns ErrInvalidCredentials, or the error of the dummy
// verification (auth.ErrBusy) wrapped.
func (s *Service) rejectAfterDummyVerify(ctx context.Context, password string) error {
	if err := s.dummyVerify(ctx, password); err != nil {
		return fmt.Errorf("verify password: %w", err)
	}
	return ErrInvalidCredentials
}

// log returns the logger of the service.
func (s *Service) log() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
}

func (s *Service) FindByID(ctx context.Context, id int64) (*sqlcgen.User, error) {
	u, err := s.q.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

func (s *Service) FindByEmail(ctx context.Context, email string) (*sqlcgen.User, error) {
	u, err := s.q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

// List returns all users ordered by id.
func (s *Service) List(ctx context.Context) ([]sqlcgen.ListUsersRow, error) {
	return s.q.ListUsers(ctx)
}

// ChangePassword is the password change of a signed-in user: it stores a
// password the user chose (ValidatePassword applies) and, in the same
// transaction, deletes every session of the user, the one the change came
// from included, and the user's open password-reset tokens. Either all of
// it happens or nothing: a database error leaves the old password and every
// session in place. A caller that wants the user to stay logged in creates
// a new session after it returned. Returns ErrNotFound for an unknown user
// and an error wrapping auth.ErrBusy when the hash could not start in time.
func (s *Service) ChangePassword(ctx context.Context, userID int64, newPassword string) error {
	if err := s.ValidatePassword(newPassword); err != nil {
		return err
	}
	return s.storePassword(ctx, userID, newPassword)
}

// SetPassword bypasses the old-password check (admin reset). The password
// is one an admin sets, so ValidateAdminPassword applies. In one
// transaction it stores the password, deletes every session of the user and
// deletes the user's open password-reset tokens: after an admin reset
// nobody stays logged in to the account and no older reset link works.
// Returns ErrNotFound for an unknown user and an error wrapping auth.ErrBusy
// when the hash could not start in time.
func (s *Service) SetPassword(ctx context.Context, userID int64, newPassword string) error {
	if err := s.ValidateAdminPassword(newPassword); err != nil {
		return err
	}
	return s.storePassword(ctx, userID, newPassword)
}

// storePassword hashes an already validated password and writes it. The
// hash runs before the transaction starts, so no connection is held during
// the KDF. In the transaction it updates the account row first (which locks
// it, the order users.Disable and passwordreset.Consume use too), then
// deletes every session of the user, then the open reset tokens.
func (s *Service) storePassword(ctx context.Context, userID int64, password string) error {
	hash, err := s.hash(ctx, password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)

	n, err := q.UpdateUserPassword(ctx, sqlcgen.UpdateUserPasswordParams{ID: userID, PasswordHash: hash})
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	if err := q.DeleteSessionsByUser(ctx, userID); err != nil {
		return fmt.Errorf("log out: %w", err)
	}
	if err := q.DeletePasswordResetsForUser(ctx, userID); err != nil {
		return fmt.Errorf("delete open resets: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// MarkEmailVerified sets email_verified_at = now() for the user.
func (s *Service) MarkEmailVerified(ctx context.Context, userID int64) error {
	return s.q.MarkUserEmailVerified(ctx, userID)
}

// VerifyPassword checks password against the stored hash of userID. It
// returns auth.ErrBusy when the check could not start in time. A password
// longer than Options.MaxPasswordBytes never matches and is not hashed. For
// a login by email address use Authenticate.
func (s *Service) VerifyPassword(ctx context.Context, userID int64, password string) (bool, error) {
	u, err := s.q.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, err
	}
	if s.tooLong(password) {
		return false, nil
	}
	return s.verify(ctx, u.PasswordHash, password)
}

// Promote sets is_admin=true. No-op if already admin.
func (s *Service) Promote(ctx context.Context, userID int64) error {
	return s.q.SetUserAdmin(ctx, sqlcgen.SetUserAdminParams{ID: userID, IsAdmin: true})
}

// lockForAdminChange locks every admin row and the target row, and reports
// the target and whether another active admin exists. Demote and Disable
// both start with it: because each of them holds all admin rows before it
// checks, two of them cannot both see "one admin left besides mine" and
// together remove the last one.
func lockForAdminChange(ctx context.Context, q *sqlcgen.Queries, userID int64) (target sqlcgen.User, otherActiveAdmin bool, err error) {
	admins, err := q.LockAdminUsers(ctx)
	if err != nil {
		return target, false, fmt.Errorf("lock admins: %w", err)
	}
	target, err = q.GetUserByIDForUpdate(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return target, false, ErrNotFound
		}
		return target, false, fmt.Errorf("lock user: %w", err)
	}
	for _, a := range admins {
		if a.ID != userID && !a.DisabledAt.Valid {
			otherActiveAdmin = true
			break
		}
	}
	return target, otherActiveAdmin, nil
}

// Demote sets is_admin=false. It returns ErrLastAdmin when the target is
// the only active admin; the check and the update are one transaction that
// holds a lock on every admin row. A disabled admin can always be demoted,
// since that takes no active admin away. Demoting a user who is no admin is
// a no-op. Returns ErrNotFound for an unknown user.
func (s *Service) Demote(ctx context.Context, userID int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)

	target, otherActiveAdmin, err := lockForAdminChange(ctx, q, userID)
	if err != nil {
		return err
	}
	if !target.IsAdmin {
		return nil
	}
	if !target.DisabledAt.Valid && !otherActiveAdmin {
		return ErrLastAdmin
	}
	if err := q.SetUserAdmin(ctx, sqlcgen.SetUserAdminParams{ID: userID, IsAdmin: false}); err != nil {
		return fmt.Errorf("demote user: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// Disable sets disabled_at=now(), deletes all sessions of the user and all
// their open password-reset tokens, in a single transaction: either all of
// it happens or none. API tokens stay in the table but stop verifying while
// the account is disabled.
//
// It returns ErrLastAdmin when the target is the only active admin and
// ErrNotFound for an unknown user.
//
// The SessionPurger argument is ignored; it remains so that existing
// callers compile. Tunnels the user has open are not closed here: the
// caller does that through the registry.
func (s *Service) Disable(ctx context.Context, _ SessionPurger, userID int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)

	target, otherActiveAdmin, err := lockForAdminChange(ctx, q, userID)
	if err != nil {
		return err
	}
	if target.IsAdmin && !target.DisabledAt.Valid && !otherActiveAdmin {
		return ErrLastAdmin
	}
	if err := q.DisableUser(ctx, userID); err != nil {
		return fmt.Errorf("disable user: %w", err)
	}
	if err := q.DeleteSessionsByUser(ctx, userID); err != nil {
		return fmt.Errorf("delete sessions: %w", err)
	}
	if err := q.DeletePasswordResetsForUser(ctx, userID); err != nil {
		return fmt.Errorf("delete open resets: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// Enable clears disabled_at for the user.
func (s *Service) Enable(ctx context.Context, userID int64) error {
	return s.q.EnableUser(ctx, userID)
}

// IsApproved reports whether an admin has approved the account. It matters
// only while auth.signup is "approval" or "closed"; in "open" mode every
// account is usable whatever this says.
func IsApproved(u *sqlcgen.User) bool {
	return u.ApprovedAt.Valid
}

// Approve marks the account as approved. Approving an approved account
// keeps the first approval time and is no error. It returns ErrNotFound
// when no account has the id, also when the account was deleted (rejected)
// after the caller looked it up: a caller then must not report it as
// approved.
func (s *Service) Approve(ctx context.Context, id int64) error {
	n, err := s.q.ApproveUser(ctx, id)
	if err != nil {
		return fmt.Errorf("approve user: %w", err)
	}
	if n > 0 {
		return nil
	}
	// No row changed: the account is approved already, or there is none.
	if _, err := s.q.GetUserByID(ctx, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("approve user: look up: %w", err)
	}
	return nil
}

// ApproveExisting approves every account that is in use already: admins
// and accounts that hold an API token or a reservation. The server calls it
// at start in approval and closed mode, so that switching to such a mode
// locks out nobody who uses the server. It returns the number of accounts it
// approved; a second call returns 0.
func (s *Service) ApproveExisting(ctx context.Context) (int64, error) {
	return s.q.ApproveExistingUsers(ctx)
}

// ListPending returns the accounts that wait for approval, oldest first:
// not approved, no admin, not disabled, and not in use: no API token (of any
// state) and no reservation. An account in use with approved_at NULL exists
// until the server has started in approval or closed mode
// (ApproveExisting); it is not listed, so that nobody rejects it.
func (s *Service) ListPending(ctx context.Context) ([]sqlcgen.ListPendingUsersRow, error) {
	return s.q.ListPendingUsers(ctx)
}

// CountPending returns the number of accounts ListPending lists.
func (s *Service) CountPending(ctx context.Context) (int64, error) {
	return s.q.CountPendingUsers(ctx)
}

// DeletePending deletes an account that waits for approval (the rejection)
// together with its sessions and everything else that belongs to it: only
// an account that ListPending lists. It returns ErrNotPending, and deletes
// nothing, when the account is unknown, approved, an admin, disabled or in
// use (an API token of any state, a reservation).
//
// The account row is locked first and the DELETE runs as a statement of its
// own in the same transaction, as in the reaper: a token or reservation
// that another transaction is adding to the account is committed before the
// lock is granted and keeps the account; on its own, the DELETE would wait
// for that transaction and then delete the account, and the new row with
// it.
func (s *Service) DeletePending(ctx context.Context, id int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)

	if _, err := q.GetUserByIDForUpdate(ctx, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotPending
		}
		return fmt.Errorf("delete pending user: lock: %w", err)
	}
	n, err := q.DeletePendingUser(ctx, id)
	if err != nil {
		return fmt.Errorf("delete pending user: %w", err)
	}
	if n == 0 {
		return ErrNotPending
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// AdminEmails returns the addresses of all admins that are not disabled.
func (s *Service) AdminEmails(ctx context.Context) ([]string, error) {
	return s.q.ListAdminEmails(ctx)
}

// CountAll returns the total number of users.
func (s *Service) CountAll(ctx context.Context) (int64, error) {
	return s.q.CountUsers(ctx)
}

// CountAdmins returns the number of non-disabled admin users.
func (s *Service) CountAdmins(ctx context.Context) (int64, error) {
	return s.q.CountAdmins(ctx)
}

// likeEscaper puts a backslash before the three characters that mean
// something in a LIKE pattern.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// escapeLike makes s safe to embed in a LIKE pattern with ESCAPE '\': the
// result matches s as text.
func escapeLike(s string) string { return likeEscaper.Replace(s) }

// Search returns users whose email contains query (empty = all), paginated
// by limit/offset, and the total count matching the query. The query is
// matched as text: %, _ and \ have no special meaning.
func (s *Service) Search(ctx context.Context, query string, limit, offset int) ([]sqlcgen.ListUsersWithSearchRow, int64, error) {
	pattern := escapeLike(query)
	rows, err := s.q.ListUsersWithSearch(ctx, sqlcgen.ListUsersWithSearchParams{
		Column1: pattern,
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	total, err := s.q.CountUsersWithSearch(ctx, pattern)
	if err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}
	return rows, total, nil
}

// IsAdmin returns true if the user exists, has is_admin=true and is not
// disabled. Returns false (not error) for missing users.
func (s *Service) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	u, err := s.q.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("get user: %w", err)
	}
	return u.IsAdmin && !u.DisabledAt.Valid, nil
}

// LookupEmails fetches emails for the given user IDs in a single batched query.
// Missing IDs are silently omitted from the result map.
func (s *Service) LookupEmails(ctx context.Context, ids []int64) (map[int64]string, error) {
	if len(ids) == 0 {
		return map[int64]string{}, nil
	}
	rows, err := s.q.GetUserEmailsByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("lookup emails: %w", err)
	}
	out := make(map[int64]string, len(rows))
	for _, r := range rows {
		out[r.ID] = r.Email
	}
	return out, nil
}
