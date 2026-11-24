// Package reaper periodically deletes expired rows from session-like tables
// and, when asked to, accounts that were never verified and never used, and
// accounts that waited too long for an admin's approval.
package reaper

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
)

// DefaultInterval is how often Run sweeps the tables.
const DefaultInterval = time.Hour

// RecommendedUnverifiedAccountTTL is the value recommended for
// Options.UnverifiedAccountTTL when an operator switches that rule on. It is
// not a default: nothing in this package uses it.
const RecommendedUnverifiedAccountTTL = 7 * 24 * time.Hour

// MinUnverifiedAccountTTL is the smallest Options.UnverifiedAccountTTL that
// switches the rule on. A shorter one would delete accounts minutes after
// the sign-up, before their owner can have read the verification mail.
const MinUnverifiedAccountTTL = time.Hour

// DefaultPendingAccountTTL is the value the server passes as
// Options.PendingAccountTTL when limits.pending_account_ttl is not set in
// approval or closed mode. It is not a default of this package either.
const DefaultPendingAccountTTL = 30 * 24 * time.Hour

// Options configures a Reaper.
type Options struct {
	// Interval is the time between sweeps. Zero or less selects
	// DefaultInterval.
	Interval time.Duration

	// UnverifiedAccountTTL switches on the deletion of accounts that were
	// never verified and never used, and is the age from which it applies.
	//
	// The rule is off unless this is positive. That is a deliberate
	// exception to "zero selects the default": the rule deletes accounts,
	// accounts can be in use without a verified address (the tunnel path
	// does not ask for one, and accounts made with the admin CLI or before
	// verification existed were never verified), so it must not start by
	// itself after an upgrade. Zero and negative values both mean off.
	// RecommendedUnverifiedAccountTTL (7 days) is the value to configure.
	//
	// A positive value below MinUnverifiedAccountTTL (one hour) leaves the
	// rule off as well, and NewWithOptions logs a warning that says so: a
	// value that small is a mistake, and the mistake must not delete
	// accounts.
	//
	// When it is on, a sweep deletes an account only if all of this holds:
	// the address is unverified; the account is older than the TTL, by the
	// database clock; it is not an admin; it is not disabled; it owns no
	// API token (revoked and expired tokens count as tokens) and no
	// subdomain, TCP port or UDP port reservation.
	UnverifiedAccountTTL time.Duration

	// PendingAccountTTL switches on the deletion of accounts that wait for
	// an admin's approval (auth.signup approval or closed), and is the age
	// from which it applies. As for UnverifiedAccountTTL, the rule is off
	// unless this is positive, and a positive value below
	// MinUnverifiedAccountTTL leaves it off with a warning: outside those
	// modes every account that was signed up has no approval, so the
	// caller sets it only in those modes (the server: 720h unless
	// limits.pending_account_ttl says otherwise).
	//
	// When it is on, a sweep deletes an account only if all of this holds:
	// it is not approved; it is older than the TTL, by the database clock;
	// it is not an admin; it is not disabled; it owns no API token (of any
	// state) and no subdomain, TCP port or UDP port reservation. Whether
	// the address is verified does not matter.
	//
	// Run leaves this rule out of the sweep it makes at start and applies
	// it from the first sweep after Interval on; at start it only logs how
	// many accounts that sweep is going to delete. When a server is switched
	// to approval or closed mode, every account that is not in use starts to
	// wait with its old creation time; the operator gets the time to look
	// through them (and to stop the server) before they go.
	PendingAccountTTL time.Duration

	// Logger receives the sweep results. nil selects slog.Default().
	Logger *slog.Logger
}

// Reaper deletes expired rows on a fixed cadence.
type Reaper struct {
	pool          *pgxpool.Pool
	interval      time.Duration
	unverifiedTTL time.Duration // <= 0: unverified accounts are left alone
	pendingTTL    time.Duration // <= 0: accounts waiting for approval are left alone
	logger        *slog.Logger
}

// New builds a reaper that deletes expired sessions and tokens. It does not
// delete accounts; for that, see Options.UnverifiedAccountTTL.
// interval <= 0 defaults to DefaultInterval.
func New(pool *pgxpool.Pool, interval time.Duration, logger *slog.Logger) *Reaper {
	return NewWithOptions(pool, Options{Interval: interval, Logger: logger})
}

// NewWithOptions builds a reaper.
func NewWithOptions(pool *pgxpool.Pool, opts Options) *Reaper {
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.UnverifiedAccountTTL > 0 && opts.UnverifiedAccountTTL < MinUnverifiedAccountTTL {
		opts.Logger.Warn("reaper: the TTL for unverified accounts is below the minimum, no account will be deleted",
			"ttl", opts.UnverifiedAccountTTL.String(), "minimum", MinUnverifiedAccountTTL.String())
		opts.UnverifiedAccountTTL = 0
	}
	if opts.PendingAccountTTL > 0 && opts.PendingAccountTTL < MinUnverifiedAccountTTL {
		opts.Logger.Warn("reaper: the TTL for accounts waiting for approval is below the minimum, no account will be deleted",
			"ttl", opts.PendingAccountTTL.String(), "minimum", MinUnverifiedAccountTTL.String())
		opts.PendingAccountTTL = 0
	}
	return &Reaper{
		pool:          pool,
		interval:      opts.Interval,
		unverifiedTTL: opts.UnverifiedAccountTTL,
		pendingTTL:    opts.PendingAccountTTL,
		logger:        opts.Logger,
	}
}

// Run loops until ctx is cancelled. Call from a goroutine.
func (r *Reaper) Run(ctx context.Context) {
	// Sweep once immediately so operators don't wait an hour for the first
	// cleanup; the rule for accounts that wait for approval waits for the
	// first tick (Options.PendingAccountTTL).
	r.sweep(ctx, false)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Sweep(ctx)
		}
	}
}

// Sweep deletes expired sessions, email verifications and password resets.
// With Options.UnverifiedAccountTTL or Options.PendingAccountTTL set it also
// deletes the accounts that option describes, and logs one line with their
// number when there were any. Errors are logged, not returned — the reaper is strictly best-effort
// and shouldn't crash the server because one query timed out.
func (r *Reaper) Sweep(ctx context.Context) {
	r.sweep(ctx, true)
}

// sweep is Sweep. Without deletePending it leaves the accounts that wait
// for approval in place and logs how many of them a sweep would delete now
// (the sweep of Run at start).
func (r *Reaper) sweep(ctx context.Context, deletePending bool) {
	q := sqlcgen.New(r.pool)
	if err := q.DeleteExpiredSessions(ctx); err != nil {
		r.logger.Warn("reaper: delete expired sessions", "err", err)
	}
	if err := q.DeleteExpiredEmailVerifications(ctx); err != nil {
		r.logger.Warn("reaper: delete expired email verifications", "err", err)
	}
	if err := q.DeleteExpiredPasswordResets(ctx); err != nil {
		r.logger.Warn("reaper: delete expired password resets", "err", err)
	}
	if r.unverifiedTTL > 0 {
		n, err := r.deleteUnverifiedAccounts(ctx)
		if err != nil {
			r.logger.Warn("reaper: delete unverified accounts", "err", err)
		} else if n > 0 {
			r.logger.Info("reaper: deleted unverified accounts", "count", n, "older_than", r.unverifiedTTL.String())
		}
	}
	if r.pendingTTL > 0 && !deletePending {
		n, err := q.CountStalePendingUsers(ctx, r.pendingTTL.Seconds())
		if err != nil {
			r.logger.Warn("reaper: count accounts waiting for approval", "err", err)
		} else {
			// Warn when accounts are due: they go in an interval, and the
			// operator may not expect it (the switch to approval mode).
			level := slog.LevelInfo
			if n > 0 {
				level = slog.LevelWarn
			}
			r.logger.Log(ctx, level, "reaper: accounts waiting for approval are not deleted at start; the next sweep deletes those due",
				"count_due", n, "older_than", r.pendingTTL.String(), "next_sweep_in", r.interval.String())
		}
	}
	if r.pendingTTL > 0 && deletePending {
		n, err := r.deletePendingAccounts(ctx)
		if err != nil {
			r.logger.Warn("reaper: delete accounts waiting for approval", "err", err)
		} else if n > 0 {
			r.logger.Info("reaper: deleted accounts waiting for approval", "count", n, "older_than", r.pendingTTL.String())
		}
	}
}

// deleteUnverifiedAccounts applies the rule of Options.UnverifiedAccountTTL
// and returns the number of accounts it deleted.
//
// It locks the accounts that meet the conditions and then deletes, of
// exactly those accounts, the ones that still meet them — two statements of
// one transaction. The DELETE therefore touches only rows this transaction
// holds a lock on. A token or reservation that another transaction was
// adding to one of them was committed before the lock was granted; the
// DELETE sees it and the account stays. One that comes later waits for the
// transaction. An account that meets the conditions only after the lock
// query has looked is left for a later sweep.
func (r *Reaper) deleteUnverifiedAccounts(ctx context.Context) (int64, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlcgen.New(tx)

	age := r.unverifiedTTL.Seconds()
	ids, err := q.LockStaleUnverifiedUsers(ctx, age)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	n, err := q.DeleteStaleUnverifiedUsers(ctx, sqlcgen.DeleteStaleUnverifiedUsersParams{Ids: ids, MaxAgeSeconds: age})
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return n, nil
}

// deletePendingAccounts applies the rule of Options.PendingAccountTTL and
// returns the number of accounts it deleted. It works as
// deleteUnverifiedAccounts, with the query pair for accounts that were never
// approved.
func (r *Reaper) deletePendingAccounts(ctx context.Context) (int64, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlcgen.New(tx)

	age := r.pendingTTL.Seconds()
	ids, err := q.LockStalePendingUsers(ctx, age)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	n, err := q.DeleteStalePendingUsers(ctx, sqlcgen.DeleteStalePendingUsersParams{Ids: ids, MaxAgeSeconds: age})
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return n, nil
}
