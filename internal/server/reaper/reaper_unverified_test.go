package reaper

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
)

type account struct {
	email    string
	age      time.Duration
	verified bool
	admin    bool
	disabled bool
}

// insertAccount creates a user row with the given age and flags. The age is
// counted back from the clock of the database, the one the sweep uses.
func insertAccount(t *testing.T, pool *pgxpool.Pool, a account) int64 {
	t.Helper()
	id := dbtest.InsertUser(t, pool, a.email)
	_, err := pool.Exec(context.Background(), `
		UPDATE users SET
			created_at        = now() - $2::double precision * interval '1 second',
			email_verified_at = CASE WHEN $3 THEN now() ELSE NULL END,
			is_admin          = $4,
			disabled_at       = CASE WHEN $5 THEN now() ELSE NULL END
		WHERE id = $1`,
		id, a.age.Seconds(), a.verified, a.admin, a.disabled)
	require.NoError(t, err)
	return id
}

func exec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	_, err := pool.Exec(context.Background(), sql, args...)
	require.NoError(t, err)
}

func userExists(t *testing.T, pool *pgxpool.Pool, id int64) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE id = $1`, id).Scan(&n))
	return n == 1
}

const day = 24 * time.Hour

// population is one account of every kind the rule has to tell apart. All
// but "fresh" are 30 days old.
type population struct {
	bare, fresh, verified, admin, disabled                       int64
	activeToken, revokedToken, expiredToken, subdomain, tcp, udp int64
}

func populate(t *testing.T, pool *pgxpool.Pool, prefix string) population {
	t.Helper()
	old := func(name string, a account) int64 {
		a.email = prefix + "-" + name + "@example.com"
		if a.age == 0 {
			a.age = 30 * day
		}
		return insertAccount(t, pool, a)
	}
	p := population{
		bare:         old("bare", account{}),
		fresh:        old("fresh", account{age: 6 * day}),
		verified:     old("verified", account{verified: true}),
		admin:        old("admin", account{admin: true}),
		disabled:     old("disabled", account{disabled: true}),
		activeToken:  old("active-token", account{}),
		revokedToken: old("revoked-token", account{}),
		expiredToken: old("expired-token", account{}),
		subdomain:    old("subdomain", account{}),
		tcp:          old("tcp", account{}),
		udp:          old("udp", account{}),
	}
	// A fixed date long ago for "revoked" and "expired": no clock involved.
	longAgo := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	const token = `INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, revoked_at, expires_at)
		VALUES ($1, 'laptop', $2, 'prefix', $3, $4)`
	exec(t, pool, token, p.activeToken, []byte(prefix+"-active"), nil, nil)
	exec(t, pool, token, p.revokedToken, []byte(prefix+"-revoked"), &longAgo, nil)
	exec(t, pool, token, p.expiredToken, []byte(prefix+"-expired"), nil, &longAgo)
	exec(t, pool, `INSERT INTO reserved_subdomains (subdomain, user_id) VALUES ($1, $2)`, prefix+"-keep", p.subdomain)
	// Ports are unique over all users; derive them from the prefix length so
	// that the two populations of the test do not collide.
	port := 20000 + len(prefix)
	exec(t, pool, `INSERT INTO reserved_tcp_ports (port, user_id) VALUES ($1, $2)`, port, p.tcp)
	exec(t, pool, `INSERT INTO reserved_udp_ports (port, user_id) VALUES ($1, $2)`, port, p.udp)
	return p
}

func (p population) all() map[string]int64 {
	return map[string]int64{
		"bare (old, unverified, owns nothing)": p.bare,
		"younger than the TTL":                 p.fresh,
		"verified":                             p.verified,
		"admin":                                p.admin,
		"disabled":                             p.disabled,
		"has an active token":                  p.activeToken,
		"has a revoked token":                  p.revokedToken,
		"has an expired token":                 p.expiredToken,
		"has a subdomain reservation":          p.subdomain,
		"has a TCP port reservation":           p.tcp,
		"has a UDP port reservation":           p.udp,
	}
}

func TestSweepAndUnverifiedAccounts(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	assert.Equal(t, 7*day, RecommendedUnverifiedAccountTTL)
	assert.Equal(t, time.Hour, MinUnverifiedAccountTTL)

	t.Run("off by default: nothing is deleted", func(t *testing.T) {
		p := populate(t, pool, "off")

		// What main.go calls today, the zero options, and a negative value.
		New(pool, time.Hour, nil).Sweep(ctx)
		NewWithOptions(pool, Options{}).Sweep(ctx)
		NewWithOptions(pool, Options{UnverifiedAccountTTL: -7 * day}).Sweep(ctx)

		for name, id := range p.all() {
			assert.True(t, userExists(t, pool, id), "%s must stay while the rule is off", name)
		}
	})

	t.Run("with a TTL of 7 days only the old, unverified, unused account goes", func(t *testing.T) {
		p := populate(t, pool, "enabled")
		var logged bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logged, nil))

		NewWithOptions(pool, Options{UnverifiedAccountTTL: 7 * day, Logger: logger}).Sweep(ctx)

		for name, id := range p.all() {
			if id == p.bare {
				assert.False(t, userExists(t, pool, id), "%s must be deleted", name)
				continue
			}
			assert.True(t, userExists(t, pool, id), "%s must stay", name)
		}

		// The first subtest's accounts are still there; its bare one is as
		// old and as unused, so this sweep took two accounts.
		lines := strings.Split(strings.TrimSpace(logged.String()), "\n")
		require.Len(t, lines, 1, "one log line for a sweep that deleted something: %q", logged.String())
		assert.Contains(t, lines[0], "count=2")
		assert.NotContains(t, lines[0], "@", "the log line names no address")

		// A second sweep finds nothing and says nothing.
		logged.Reset()
		NewWithOptions(pool, Options{UnverifiedAccountTTL: 7 * day, Logger: logger}).Sweep(ctx)
		assert.Empty(t, logged.String())
	})

	t.Run("the TTL is the one that was passed", func(t *testing.T) {
		young := insertAccount(t, pool, account{email: "ttl-young@example.com", age: 30 * time.Minute})
		old := insertAccount(t, pool, account{email: "ttl-old@example.com", age: 2 * time.Hour})

		NewWithOptions(pool, Options{UnverifiedAccountTTL: time.Hour}).Sweep(ctx)

		assert.True(t, userExists(t, pool, young), "30 minutes old, TTL one hour")
		assert.False(t, userExists(t, pool, old), "two hours old, TTL one hour")
	})

	t.Run("a token that is created while the sweep runs keeps its account", func(t *testing.T) {
		id := insertAccount(t, pool, account{email: "first-token@example.com", age: 30 * day})

		// Another transaction has inserted the account's first token and has
		// not committed. The sweep cannot see the token yet; it has to wait
		// for the account row, on which the insert holds a lock.
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, `INSERT INTO api_tokens (user_id, name, token_hash, token_prefix)
			VALUES ($1, 'laptop', $2, 'prefix')`, id, []byte("first-token"))
		require.NoError(t, err)

		inserter := backendPID(t, tx)

		swept := make(chan struct{})
		go func() {
			defer close(swept)
			NewWithOptions(pool, Options{UnverifiedAccountTTL: 7 * day}).Sweep(ctx)
		}()
		require.Eventually(t, func() bool { return blockedBy(pool, inserter) },
			10*time.Second, 10*time.Millisecond, "the sweep must wait for the account row")

		require.NoError(t, tx.Commit(ctx))
		select {
		case <-swept:
		case <-time.After(10 * time.Second):
			t.Fatal("the sweep did not finish after the insert was committed")
		}

		assert.True(t, userExists(t, pool, id), "the account has a token now and must stay")
		assert.Equal(t, 1, tokenCount(t, pool, id), "the token must not go with the account")
	})

	t.Run("an account that becomes a candidate while the sweep runs is not deleted by it", func(t *testing.T) {
		// "late" owns a reservation when the sweep starts, so the sweep does
		// not lock it. "held" is a candidate whose first token is inserted
		// and not committed: the sweep waits for it, after it has decided
		// which accounts it locks.
		late := insertAccount(t, pool, account{email: "late-candidate@example.com", age: 30 * day})
		exec(t, pool, `INSERT INTO reserved_subdomains (subdomain, user_id) VALUES ('late-candidate', $1)`, late)
		held := insertAccount(t, pool, account{email: "holds-the-sweep@example.com", age: 30 * day})

		const token = `INSERT INTO api_tokens (user_id, name, token_hash, token_prefix)
			VALUES ($1, 'laptop', $2, 'prefix')`
		holder, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = holder.Rollback(ctx) }()
		_, err = holder.Exec(ctx, token, held, []byte("holds-the-sweep"))
		require.NoError(t, err)
		holderPID := backendPID(t, holder)

		swept := make(chan struct{})
		go func() {
			defer close(swept)
			NewWithOptions(pool, Options{UnverifiedAccountTTL: 7 * day}).Sweep(ctx)
		}()
		require.Eventually(t, func() bool { return blockedBy(pool, holderPID) },
			10*time.Second, 10*time.Millisecond, "the sweep must wait for the account row")

		// While the sweep waits, "late" gives up its reservation, which makes
		// it a candidate, and its first token is inserted and not committed.
		exec(t, pool, `DELETE FROM reserved_subdomains WHERE user_id = $1`, late)
		first, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = first.Rollback(ctx) }()
		_, err = first.Exec(ctx, token, late, []byte("late-candidate"))
		require.NoError(t, err)
		firstPID := backendPID(t, first)

		// The sweep goes on. It did not lock "late" and must leave it alone.
		// A sweep that waits for the insert here deletes the account, and
		// the token with it, as soon as the insert is committed.
		require.NoError(t, holder.Commit(ctx))
		require.Eventually(t, func() bool {
			select {
			case <-swept:
				return true
			default:
				return blockedBy(pool, firstPID)
			}
		}, 10*time.Second, 10*time.Millisecond, "the sweep neither finished nor waited")
		require.NoError(t, first.Commit(ctx))
		select {
		case <-swept:
		case <-time.After(10 * time.Second):
			t.Fatal("the sweep did not finish")
		}

		assert.True(t, userExists(t, pool, late), "the account that became a candidate during the sweep must stay")
		assert.Equal(t, 1, tokenCount(t, pool, late), "its token must not go with it")
		assert.True(t, userExists(t, pool, held), "the account the sweep waited for has a token now and must stay")
		assert.Equal(t, 1, tokenCount(t, pool, held))
	})

	t.Run("a TTL of less than an hour leaves the rule off and is reported once", func(t *testing.T) {
		old := insertAccount(t, pool, account{email: "below-minimum@example.com", age: 2 * time.Hour})
		var logged bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logged, nil))

		// One nanosecond below the minimum.
		r := NewWithOptions(pool, Options{UnverifiedAccountTTL: time.Hour - time.Nanosecond, Logger: logger})
		assert.Equal(t, 1, strings.Count(logged.String(), "level=WARN"),
			"one warning when the reaper is created: %q", logged.String())
		assert.Contains(t, logged.String(), "59m59.999999999s", "the warning names the value")
		assert.Contains(t, logged.String(), "1h0m0s", "the warning names the minimum")

		logged.Reset()
		r.Sweep(ctx)
		r.Sweep(ctx)
		assert.True(t, userExists(t, pool, old), "two hours old, but the TTL is below the minimum: the rule is off")
		assert.Empty(t, logged.String(), "the sweeps add nothing to the warning")

		// Zero and negative values are the documented "off": no warning.
		NewWithOptions(pool, Options{Logger: logger})
		NewWithOptions(pool, Options{UnverifiedAccountTTL: -time.Minute, Logger: logger})
		assert.Empty(t, logged.String())

		// The minimum itself is allowed: no warning, and the rule runs.
		NewWithOptions(pool, Options{UnverifiedAccountTTL: time.Hour, Logger: logger}).Sweep(ctx)
		assert.False(t, userExists(t, pool, old), "two hours old, TTL one hour")
		assert.NotContains(t, logged.String(), "level=WARN")
	})
}

func TestReaperDeletesStalePending(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	// Verified, so that only the rule for waiting accounts can take them.
	stale := insertAccount(t, pool, account{email: "pending-31@example.com", age: 31 * day, verified: true})
	young := insertAccount(t, pool, account{email: "pending-29@example.com", age: 29 * day, verified: true})
	approved := insertAccount(t, pool, account{email: "approved-old@example.com", age: 60 * day, verified: true})
	exec(t, pool, `UPDATE users SET approved_at = now() - interval '59 days' WHERE id = $1`, approved)
	// Old and never approved, but not an account that waits: an admin, a
	// disabled account, and one in use (a revoked token counts).
	admin := insertAccount(t, pool, account{email: "admin-old@example.com", age: 60 * day, verified: true, admin: true})
	disabled := insertAccount(t, pool, account{email: "disabled-old@example.com", age: 60 * day, verified: true, disabled: true})
	revoked := insertAccount(t, pool, account{email: "revoked-token@example.com", age: 60 * day, verified: true})
	longAgo := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	exec(t, pool, `INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, revoked_at)
		VALUES ($1, 'laptop', 'revoked-pending', 'prefix', $2)`, revoked, &longAgo)

	NewWithOptions(pool, Options{PendingAccountTTL: DefaultPendingAccountTTL}).Sweep(ctx)

	assert.False(t, userExists(t, pool, stale), "waits for 31 days: deleted")
	assert.True(t, userExists(t, pool, young), "waits for 29 days: stays")
	assert.True(t, userExists(t, pool, approved), "approved long ago: stays")
	assert.True(t, userExists(t, pool, admin), "an admin without approval: stays")
	assert.True(t, userExists(t, pool, disabled), "a disabled account: stays")
	assert.True(t, userExists(t, pool, revoked), "an account with a revoked token: stays")
	assert.Equal(t, 1, tokenCount(t, pool, revoked), "and its token with it")
}

// The sweep that Run makes at start leaves the accounts that wait for
// approval alone and logs how many are due; the sweeps after the interval
// delete them. A server that is switched to approval mode thus does not
// delete accounts the moment it starts.
func TestRunDeletesPendingAccountsFromTheFirstTickOn(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	stale := insertAccount(t, pool, account{email: "stale-pending@example.com", age: 31 * day, verified: true})
	newReaper := func(interval time.Duration, logs *lockedBuffer) *Reaper {
		return NewWithOptions(pool, Options{
			Interval: interval, PendingAccountTTL: DefaultPendingAccountTTL,
			Logger: slog.New(slog.NewTextHandler(logs, nil)),
		})
	}

	// The start sweep (what Run calls first) deletes nothing that waits.
	var logs lockedBuffer
	newReaper(time.Hour, &logs).sweep(ctx, false)
	assert.True(t, userExists(t, pool, stale), "the start sweep deletes no account that waits")
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "count_due=1")
	assert.Contains(t, logs.String(), "older_than=720h0m0s")
	assert.Contains(t, logs.String(), "next_sweep_in=1h0m0s")
	assert.NotContains(t, logs.String(), "stale-pending@example.com", "the log line names no address")

	// Run: the start sweep reports the account, the first tick deletes it.
	logs = lockedBuffer{}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); newReaper(50*time.Millisecond, &logs).Run(runCtx) }()
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "reaper: deleted accounts waiting for approval") },
		10*time.Second, 10*time.Millisecond, "a tick deletes the account that is due: %q", logs.String())
	cancel()
	<-done
	assert.False(t, userExists(t, pool, stale))
	assert.Contains(t, logs.String(), "count_due=1", "Run starts with the sweep that only counts")
}

// lockedBuffer is a log sink that the reaper's goroutine and the test can
// use at the same time.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// backendPID returns the id of the server process that runs tx.
func backendPID(t *testing.T, tx pgx.Tx) int32 {
	t.Helper()
	var pid int32
	require.NoError(t, tx.QueryRow(context.Background(), `SELECT pg_backend_pid()`).Scan(&pid))
	return pid
}

// blockedBy reports whether a session of this database waits for a lock
// that the server process pid holds.
func blockedBy(pool *pgxpool.Pool, pid int32) bool {
	var waiting int
	err := pool.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity
		WHERE datname = current_database() AND wait_event_type = 'Lock'
		  AND $1::int = ANY(pg_blocking_pids(pid))`, pid).Scan(&waiting)
	return err == nil && waiting > 0
}

func tokenCount(t *testing.T, pool *pgxpool.Pool, userID int64) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), `SELECT count(*) FROM api_tokens WHERE user_id = $1`, userID).Scan(&n))
	return n
}
