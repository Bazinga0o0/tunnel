// Package reservations persists and queries subdomain ownership records.
package reservations

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
)

var (
	ErrAlreadyReserved = errors.New("subdomain already reserved")
	ErrNotOwned        = errors.New("reservation does not belong to user")

	// ErrInvalidSubdomain is returned for a name that is not a well-formed
	// subdomain label (see NormalizeSubdomain).
	ErrInvalidSubdomain = errors.New("invalid subdomain")

	// ErrSystemReserved is returned for a well-formed name that is on the
	// system-reserved list.
	ErrSystemReserved = errors.New("subdomain is reserved for system use")

	// ErrReservationLimit is returned by Reserve when the user already holds
	// the maximum number of subdomain reservations.
	ErrReservationLimit = errors.New("reservation limit reached")

	// ErrInvalidPort is returned by every port method for a port outside
	// 1–65535.
	ErrInvalidPort = errors.New("port out of range")

	// ErrUnknownUser is returned by TransferTCPPort for a user ID that names
	// no account.
	ErrUnknownUser = errors.New("unknown user")
)

// SystemReservedNames lists subdomains that can never be claimed or
// reserved by users; they're used by the service itself, or a visitor would
// take a host of that name for a part of the service.
var SystemReservedNames = []string{
	// Used by the service itself.
	"www", "api", "app", "admin", "dashboard", "status", "static", "cdn",
	"assets", "metrics", "tunnel", "internal",
	// Account and sign-in pages a visitor would trust.
	"login", "signin", "logout", "signup", "register", "auth", "oauth", "sso",
	"account", "billing", "support", "help", "docs", "security",
	// Mail, DNS and other infrastructure host names. (Two-letter names such as
	// "mx" or "ns" need no entry: NormalizeSubdomain rejects them as too short.)
	"mail", "webmail", "smtp", "imap", "pop", "pop3", "ftp",
	"ns1", "ns2", "autoconfig", "autodiscover", "wpad", "localhost",
}

// AddSystemReserved adds names to SystemReservedNames, so that no tunnel and
// no reservation can take them: the subdomains of the registered services.
// It is called at start-up, before the server takes requests; the list is
// read without a lock. Names already on the list are skipped.
func AddSystemReserved(names ...string) {
	for _, name := range names {
		if !IsSystemReserved(name) {
			SystemReservedNames = append(SystemReservedNames, name)
		}
	}
}

// IsSystemReserved reports whether subdomain is in the reserved blocklist.
func IsSystemReserved(subdomain string) bool {
	for _, n := range SystemReservedNames {
		if strings.EqualFold(n, subdomain) {
			return true
		}
	}
	return false
}

// subdomainRE is the shape of a normalised subdomain: one DNS label of 3 to
// 63 characters, lower-case letters, digits and inner hyphens.
var subdomainRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

// maxSubdomainLen is the longest name subdomainRE accepts.
const maxSubdomainLen = 63

// NormalizeSubdomain turns a user-supplied subdomain into the form that is
// stored and compared: surrounding white space is trimmed and ASCII letters
// are lower-cased. It returns ErrInvalidSubdomain when the result does not
// match ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ and ErrSystemReserved when it is on
// the system-reserved list. On error the returned name is empty.
//
// Every place that accepts a subdomain from outside (tunnel registration,
// reservation, admin grant, CLI) must use the returned name, so that "MyApp"
// and "myapp" are one name everywhere.
func NormalizeSubdomain(name string) (string, error) {
	name = strings.TrimSpace(name)
	if len(name) > maxSubdomainLen {
		return "", ErrInvalidSubdomain
	}
	// Lower-case ASCII only. strings.ToLower also maps a few non-ASCII letters
	// to ASCII ones (U+212A KELVIN SIGN becomes "k") and would turn a name that
	// must be rejected into a valid one.
	b := []byte(name)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	name = string(b)
	if !subdomainRE.MatchString(name) {
		return "", ErrInvalidSubdomain
	}
	if IsSystemReserved(name) {
		return "", ErrSystemReserved
	}
	return name, nil
}

// DefaultMaxSubdomainsPerUser is the number of subdomains a user may reserve
// when Options.MaxSubdomainsPerUser is zero.
const DefaultMaxSubdomainsPerUser = 10

// Options configures a Service. A zero value selects the default; a negative
// value disables the limit.
type Options struct {
	// MaxSubdomainsPerUser caps the subdomain reservations a user can hold
	// when calling Reserve. Zero selects DefaultMaxSubdomainsPerUser, a
	// negative value disables the limit. Admin grants (GrantSubdomain) are not
	// limited, but granted names count towards the user's total.
	MaxSubdomainsPerUser int
}

type Service struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
	// maxSubdomainsPerUser is the resolved limit; 0 means unlimited.
	maxSubdomainsPerUser int
}

// NewService returns a Service with the default Options.
func NewService(pool *pgxpool.Pool) *Service {
	return NewServiceWithOptions(pool, Options{})
}

// NewServiceWithOptions returns a Service with the given limits.
func NewServiceWithOptions(pool *pgxpool.Pool, opts Options) *Service {
	limit := opts.MaxSubdomainsPerUser
	switch {
	case limit == 0:
		limit = DefaultMaxSubdomainsPerUser
	case limit < 0:
		limit = 0
	}
	return &Service{pool: pool, q: sqlcgen.New(pool), maxSubdomainsPerUser: limit}
}

// reservationLockClass is the first key of the two-key advisory lock that
// serialises the reservations of one user (the second key is derived from the
// user ID). The two-key lock space is separate from the one-key space.
const reservationLockClass int32 = 0x54554e52 // "TUNR"

// userLockKey folds a user ID into the 32 bits of an advisory lock key. Two
// users that fold to the same key merely wait for each other.
func userLockKey(userID int64) int32 {
	return int32(uint32(userID) ^ uint32(userID>>32))
}

// insertSubdomain stores an already normalised name. op prefixes the error.
func insertSubdomain(ctx context.Context, q *sqlcgen.Queries, name string, userID int64, op string) error {
	_, err := q.CreateReservedSubdomain(ctx, sqlcgen.CreateReservedSubdomainParams{
		Subdomain: name, UserID: userID,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAlreadyReserved
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// Reserve takes exclusive ownership of subdomain for userID. The name is
// normalised with NormalizeSubdomain and stored in that form; the errors of
// NormalizeSubdomain are returned as they are. Reserve returns
// ErrReservationLimit when the user already holds the configured maximum
// number of subdomains.
func (s *Service) Reserve(ctx context.Context, subdomain string, userID int64) error {
	name, err := NormalizeSubdomain(subdomain)
	if err != nil {
		return err
	}
	if s.maxSubdomainsPerUser <= 0 {
		return insertSubdomain(ctx, s.q, name, userID, "reserve")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("reserve: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	// Count and insert must not interleave with another Reserve of the same
	// user, or two calls could both count below the limit and both insert.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::int, $2::int)`,
		reservationLockClass, userLockKey(userID)); err != nil {
		return fmt.Errorf("reserve: %w", err)
	}
	q := s.q.WithTx(tx)
	held, err := q.CountReservedSubdomainsByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("reserve: %w", err)
	}
	if held >= int64(s.maxSubdomainsPerUser) {
		return ErrReservationLimit
	}
	if err := insertSubdomain(ctx, q, name, userID, "reserve"); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("reserve: %w", err)
	}
	return nil
}

// Owner returns (userID, true) if subdomain is reserved, (0, false) otherwise.
// The lookup is exact: pass a name normalised with NormalizeSubdomain.
func (s *Service) Owner(ctx context.Context, subdomain string) (int64, bool, error) {
	row, err := s.q.GetReservedSubdomain(ctx, subdomain)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return row.UserID, true, nil
}

// ListByUser returns all reservations owned by userID.
func (s *Service) ListByUser(ctx context.Context, userID int64) ([]sqlcgen.ReservedSubdomain, error) {
	return s.q.ListReservedSubdomainsByUser(ctx, userID)
}

// ListAll returns every reservation in the system.
func (s *Service) ListAll(ctx context.Context) ([]sqlcgen.ReservedSubdomain, error) {
	return s.q.ListAllReservedSubdomains(ctx)
}

// Release drops a reservation, but only if userID is the current owner.
// If the subdomain isn't reserved, Release is a no-op.
func (s *Service) Release(ctx context.Context, subdomain string, userID int64) error {
	owner, reserved, err := s.Owner(ctx, subdomain)
	if err != nil {
		return err
	}
	if !reserved {
		return nil
	}
	if owner != userID {
		return ErrNotOwned
	}
	return s.q.DeleteReservedSubdomainForUser(ctx, sqlcgen.DeleteReservedSubdomainForUserParams{
		Subdomain: subdomain, UserID: userID,
	})
}

// minPort and maxPort bound the port arguments of this package.
const (
	minPort = 1
	maxPort = 65535
)

// dbPort validates port and converts it for the database, whose port columns
// are 32-bit. The range check comes first: converting an out-of-range int
// would silently keep only its low 32 bits (4294967376 would become 80).
func dbPort(port int) (int32, error) {
	if port < minPort || port > maxPort {
		return 0, ErrInvalidPort
	}
	return int32(port), nil
}

// ReserveTCPPort claims port for userID.
func (s *Service) ReserveTCPPort(ctx context.Context, port int, userID int64) error {
	p, err := dbPort(port)
	if err != nil {
		return err
	}
	_, err = s.q.CreateReservedTCPPort(ctx, sqlcgen.CreateReservedTCPPortParams{
		Port:   p,
		UserID: userID,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAlreadyReserved
		}
		return fmt.Errorf("reserve tcp port: %w", err)
	}
	return nil
}

// OwnerTCPPort returns the owning user_id (and true) if port is reserved.
func (s *Service) OwnerTCPPort(ctx context.Context, port int) (int64, bool, error) {
	p, err := dbPort(port)
	if err != nil {
		return 0, false, err
	}
	row, err := s.q.GetReservedTCPPort(ctx, p)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return row.UserID, true, nil
}

// ListTCPPortsByUser returns all TCP-port reservations owned by userID.
func (s *Service) ListTCPPortsByUser(ctx context.Context, userID int64) ([]sqlcgen.ReservedTcpPort, error) {
	return s.q.ListReservedTCPPortsByUser(ctx, userID)
}

// ReleaseTCPPort drops a TCP-port reservation owned by userID. No-op if the
// port isn't reserved; ErrNotOwned if owned by someone else.
func (s *Service) ReleaseTCPPort(ctx context.Context, port int, userID int64) error {
	p, err := dbPort(port)
	if err != nil {
		return err
	}
	owner, reserved, err := s.OwnerTCPPort(ctx, port)
	if err != nil {
		return err
	}
	if !reserved {
		return nil
	}
	if owner != userID {
		return ErrNotOwned
	}
	return s.q.DeleteReservedTCPPortForUser(ctx, sqlcgen.DeleteReservedTCPPortForUserParams{
		Port: p, UserID: userID,
	})
}

// ReserveUDPPort claims UDP port for userID.
func (s *Service) ReserveUDPPort(ctx context.Context, port int, userID int64) error {
	p, err := dbPort(port)
	if err != nil {
		return err
	}
	_, err = s.q.CreateReservedUDPPort(ctx, sqlcgen.CreateReservedUDPPortParams{
		Port:   p,
		UserID: userID,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAlreadyReserved
		}
		return fmt.Errorf("reserve udp port: %w", err)
	}
	return nil
}

// OwnerUDPPort returns the owning user_id (and true) if UDP port is reserved.
func (s *Service) OwnerUDPPort(ctx context.Context, port int) (int64, bool, error) {
	p, err := dbPort(port)
	if err != nil {
		return 0, false, err
	}
	row, err := s.q.GetReservedUDPPort(ctx, p)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return row.UserID, true, nil
}

// ListUDPPortsByUser returns all UDP-port reservations owned by userID.
func (s *Service) ListUDPPortsByUser(ctx context.Context, userID int64) ([]sqlcgen.ReservedUdpPort, error) {
	return s.q.ListReservedUDPPortsByUser(ctx, userID)
}

// ReleaseUDPPort drops a UDP-port reservation owned by userID. No-op if the
// port isn't reserved; ErrNotOwned if owned by someone else.
func (s *Service) ReleaseUDPPort(ctx context.Context, port int, userID int64) error {
	p, err := dbPort(port)
	if err != nil {
		return err
	}
	owner, reserved, err := s.OwnerUDPPort(ctx, port)
	if err != nil {
		return err
	}
	if !reserved {
		return nil
	}
	if owner != userID {
		return ErrNotOwned
	}
	return s.q.DeleteReservedUDPPortForUser(ctx, sqlcgen.DeleteReservedUDPPortForUserParams{
		Port: p, UserID: userID,
	})
}

// ---- Admin-only parallel methods ----------------------------------------
//
// These operate without owner checks and are intended exclusively for admin
// endpoints. The existing self-service Reserve/Release/etc. are unchanged.

// ListAllSubdomains returns every subdomain reservation in the system.
func (s *Service) ListAllSubdomains(ctx context.Context) ([]sqlcgen.ReservedSubdomain, error) {
	return s.q.ListAllReservedSubdomains(ctx)
}

// ListAllTCPPorts returns every TCP-port reservation in the system.
func (s *Service) ListAllTCPPorts(ctx context.Context) ([]sqlcgen.ReservedTcpPort, error) {
	return s.q.ListAllReservedTCPPorts(ctx)
}

// ListAllUDPPorts returns every UDP-port reservation in the system.
func (s *Service) ListAllUDPPorts(ctx context.Context) ([]sqlcgen.ReservedUdpPort, error) {
	return s.q.ListAllReservedUDPPorts(ctx)
}

// GrantSubdomain creates a subdomain reservation for any userID (admin path).
// The name is normalised and validated like in Reserve; the per-user limit
// does not apply.
func (s *Service) GrantSubdomain(ctx context.Context, subdomain string, userID int64) error {
	name, err := NormalizeSubdomain(subdomain)
	if err != nil {
		return err
	}
	return insertSubdomain(ctx, s.q, name, userID, "grant subdomain")
}

// GrantTCPPort creates a TCP-port reservation for any userID (admin path).
func (s *Service) GrantTCPPort(ctx context.Context, port int, userID int64) error {
	p, err := dbPort(port)
	if err != nil {
		return err
	}
	_, err = s.q.CreateReservedTCPPort(ctx, sqlcgen.CreateReservedTCPPortParams{
		Port:   p,
		UserID: userID,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAlreadyReserved
		}
		return fmt.Errorf("grant tcp port: %w", err)
	}
	return nil
}

// GrantUDPPort creates a UDP-port reservation for any userID (admin path).
func (s *Service) GrantUDPPort(ctx context.Context, port int, userID int64) error {
	p, err := dbPort(port)
	if err != nil {
		return err
	}
	_, err = s.q.CreateReservedUDPPort(ctx, sqlcgen.CreateReservedUDPPortParams{
		Port:   p,
		UserID: userID,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAlreadyReserved
		}
		return fmt.Errorf("grant udp port: %w", err)
	}
	return nil
}

// TransferTCPPort reserves port for userID, whoever held it before, and
// returns the previous owner (0 when the port was not reserved). It is the
// service API's holder change; the caller closes the session that holds the
// port. It returns ErrUnknownUser when userID names no account.
func (s *Service) TransferTCPPort(ctx context.Context, port int, userID int64) (prevUserID int64, err error) {
	p, err := dbPort(port)
	if err != nil {
		return 0, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("transfer tcp port: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	// The row lock holds a concurrent transfer or revoke of the same port
	// until the commit, so that each one reports the owner it replaced. That
	// needs a row: on a port without a reservation there is nothing to lock,
	// two concurrent transfers both report 0 and the later one's owner stays.
	q := s.q.WithTx(tx)
	switch prev, err := q.LockReservedTCPPort(ctx, p); {
	case err == nil:
		prevUserID = prev
	case !errors.Is(err, pgx.ErrNoRows):
		return 0, fmt.Errorf("transfer tcp port: %w", err)
	}
	err = q.UpsertReservedTCPPort(ctx, sqlcgen.UpsertReservedTCPPortParams{Port: p, UserID: userID})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" { // foreign_key_violation
			return 0, ErrUnknownUser
		}
		return 0, fmt.Errorf("transfer tcp port: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("transfer tcp port: %w", err)
	}
	return prevUserID, nil
}

// RevokeSubdomain deletes a subdomain reservation regardless of owner (admin path).
func (s *Service) RevokeSubdomain(ctx context.Context, subdomain string) error {
	return s.q.DeleteReservedSubdomain(ctx, subdomain)
}

// RevokeTCPPort deletes a TCP-port reservation regardless of owner (admin path).
func (s *Service) RevokeTCPPort(ctx context.Context, port int) error {
	p, err := dbPort(port)
	if err != nil {
		return err
	}
	return s.q.DeleteReservedTCPPort(ctx, p)
}

// RevokeTCPPortReturningOwner deletes the reservation of port, whoever owns
// it, and returns the owner it removed (false when the port was not
// reserved). It is the service API's holder removal; the caller closes the
// session that holds the port. Lock, read and delete are one statement, one
// transaction: while a transfer of the port holds the row, the revoke waits;
// once the transfer commits, the revoke deletes the row as the transfer left
// it and names the transfer's owner, not a stale one read before.
func (s *Service) RevokeTCPPortReturningOwner(ctx context.Context, port int) (prevUserID int64, reserved bool, err error) {
	p, err := dbPort(port)
	if err != nil {
		return 0, false, err
	}
	prev, err := s.q.DeleteReservedTCPPortReturningOwner(ctx, p)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("revoke tcp port: %w", err)
	}
	return prev, true, nil
}

// RevokeUDPPort deletes a UDP-port reservation regardless of owner (admin path).
func (s *Service) RevokeUDPPort(ctx context.Context, port int) error {
	p, err := dbPort(port)
	if err != nil {
		return err
	}
	return s.q.DeleteReservedUDPPort(ctx, p)
}

// ---- End admin-only methods ----------------------------------------

// CountSubdomains returns the total number of reserved subdomains.
func (s *Service) CountSubdomains(ctx context.Context) (int64, error) {
	return s.q.CountReservedSubdomains(ctx)
}

// CountTCPPorts returns the total number of reserved TCP ports.
func (s *Service) CountTCPPorts(ctx context.Context) (int64, error) {
	return s.q.CountReservedTCPPorts(ctx)
}

// CountUDPPorts returns the total number of reserved UDP ports.
func (s *Service) CountUDPPorts(ctx context.Context) (int64, error) {
	return s.q.CountReservedUDPPorts(ctx)
}

// CountSubdomainsByUser returns the number of subdomain reservations for userID.
func (s *Service) CountSubdomainsByUser(ctx context.Context, userID int64) (int64, error) {
	return s.q.CountReservedSubdomainsByUser(ctx, userID)
}

// CountTCPPortsByUser returns the number of TCP-port reservations for userID.
func (s *Service) CountTCPPortsByUser(ctx context.Context, userID int64) (int64, error) {
	return s.q.CountReservedTCPPortsByUser(ctx, userID)
}

// CountUDPPortsByUser returns the number of UDP-port reservations for userID.
func (s *Service) CountUDPPortsByUser(ctx context.Context, userID int64) (int64, error) {
	return s.q.CountReservedUDPPortsByUser(ctx, userID)
}
