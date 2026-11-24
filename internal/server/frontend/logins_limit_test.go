package frontend

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
)

// countHashes counts, for the rest of the test, the password-hash
// operations that see password.
func countHashes(t *testing.T, password string) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	restore := auth.SetKDFHookForTesting(func(pw string) {
		if pw == password {
			n.Add(1)
		}
	})
	t.Cleanup(restore)
	return &n
}

// countHashesOf is countHashes for several passwords at once (only one KDF
// hook can be installed at a time).
func countHashesOf(t *testing.T, passwords ...string) map[string]*atomic.Int32 {
	t.Helper()
	counts := map[string]*atomic.Int32{}
	for _, pw := range passwords {
		counts[pw] = new(atomic.Int32)
	}
	restore := auth.SetKDFHookForTesting(func(pw string) {
		if n, ok := counts[pw]; ok {
			n.Add(1)
		}
	})
	t.Cleanup(restore)
	return counts
}

// perRequestValues matches the parts of a page that differ from request to
// request: the CSRF token and the CSP nonce.
var perRequestValues = regexp.MustCompile(`(name="gorilla.csrf.Token" value=|nonce=)"[^"]*"`)

func samePage(a, b string) bool {
	return perRequestValues.ReplaceAllString(a, "$1\"…\"") == perRequestValues.ReplaceAllString(b, "$1\"…\"")
}

func TestLoginsPerAccountCountSuccessfulLogins(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) { o.LoginsPerAccount = 3 })
	s.createUser(t, "busy@example.com", "pw12345678")
	hashes := countHashes(t, "pw12345678")
	lim := limitersOf(t, s.h)

	// Wrong passwords, as many as the limit, do not move the count.
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusUnauthorized, s.login(t, "198.51.100.169:1", "busy@example.com", "wrong-password").Code)
	}
	assert.Zero(t, lim.logins.count(accountKey("busy@example.com")), "failures are not counted")

	// Successful logins from three addresses: each one counts.
	for i, peer := range []string{"198.51.100.170:1", "198.51.100.171:1", "198.51.100.172:1"} {
		require.Equal(t, http.StatusSeeOther, s.login(t, peer, "busy@example.com", "pw12345678").Code, "login %d", i+1)
	}
	require.EqualValues(t, 3, hashes.Load())
	require.Equal(t, 3, lim.logins.count(accountKey("busy@example.com")))

	// The fourth is refused before any hash, from any address and in any
	// spelling of the address.
	for _, email := range []string{"busy@example.com", " BUSY@example.com"} {
		w := s.login(t, "198.51.100.173:1", email, "pw12345678")
		require.Equal(t, http.StatusTooManyRequests, w.Code, email)
		assert.Contains(t, w.Body.String(), msgTooManyLoginsAccount)
		assert.Positive(t, retryAfterSeconds(t, w))
		assert.Nil(t, findCookie(w, "tunneld_session"))
	}
	assert.EqualValues(t, 3, hashes.Load(), "no hash over the limit")

	// The failure limits are what they were: the three wrong passwords
	// count there, the refused logins were no failures.
	assert.Equal(t, 3, lim.loginAccount.count(accountKey("busy@example.com")))

	// A wrong password at the limit is refused the same way, before any
	// hash, and does not move the count either.
	w := s.login(t, "198.51.100.173:1", "busy@example.com", "wrong-password")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), msgTooManyLoginsAccount)
	assert.Equal(t, 3, lim.logins.count(accountKey("busy@example.com")))

	s.clock.Advance(15*time.Minute + time.Second)
	require.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.173:1", "busy@example.com", "pw12345678").Code)
	assert.Equal(t, 1, lim.logins.count(accountKey("busy@example.com")), "the window")
}

// cookieNames lists the names of the cookies a response sets.
func cookieNames(w *httptest.ResponseRecorder) []string {
	var names []string
	for _, c := range w.Result().Cookies() {
		names = append(names, c.Name)
	}
	return names
}

// An outsider who sends wrong passwords for an address gets the same
// answers, step by step, whether the address has no account or has one
// whose owner logged in successfully k times in the window (k below the
// limit): the logins limit counts successful logins only and refuses
// nobody below the limit, and the failure limits count the outsider's
// failures alike. With the failure limit per account switched off, the
// logins limit refuses the outsider at no point and does not lock the
// owner out: it is no lever to keep an account out of the web UI.
func TestLoginsPerAccountRevealNothingToOutsiders(t *testing.T) {
	const ownerLogins = 25 // below the default limit of 30
	for _, c := range []struct {
		name     string
		mutate   []func(*Options, *stack)
		attempts int
	}{
		// Through the failure limit of 10 per account.
		{"default limits", nil, 12},
		// More attempts than the logins limit.
		{"failure limit per account off", []func(*Options, *stack){func(o *Options, _ *stack) {
			o.LoginFailuresPerAccount = -1
		}}, DefaultLoginsPerAccount + 5},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newStack(t, c.mutate...)
			s.createUser(t, "owner@example.com", "pw12345678")
			for i := 0; i < ownerLogins; i++ {
				require.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.230:1", "owner@example.com", "pw12345678").Code)
			}

			// The outsider takes turns between two addresses, so that
			// neither reaches the failure limit per address (30).
			answers := func(email string, peers ...string) []*httptest.ResponseRecorder {
				var out []*httptest.ResponseRecorder
				for i := 0; i < c.attempts; i++ {
					out = append(out, s.login(t, peers[i%len(peers)], email, "wrong-password"))
				}
				return out
			}
			owner := answers("owner@example.com", "198.51.100.231:1", "198.51.100.232:1")
			ghost := answers("ghost@example.com", "198.51.100.233:1", "198.51.100.234:1")
			for i := range owner {
				o, g := owner[i], ghost[i]
				require.Equal(t, g.Code, o.Code, "attempt %d", i+1)
				assert.Equal(t, g.Header().Get("Retry-After"), o.Header().Get("Retry-After"), "attempt %d", i+1)
				assert.Equal(t, g.Header().Get("Content-Type"), o.Header().Get("Content-Type"), "attempt %d", i+1)
				assert.Equal(t, cookieNames(g), cookieNames(o), "attempt %d", i+1)
				assert.True(t, samePage(o.Body.String(), g.Body.String()),
					"attempt %d: the answer does not tell the account from a missing one:\n%s\n%s", i+1, o.Body.String(), g.Body.String())
				assert.NotContains(t, o.Body.String(), msgTooManyLoginsAccount, "attempt %d", i+1)
			}
			if c.attempts > DefaultLoginFailuresPerAccount && c.mutate == nil {
				// With the defaults the failure limit refuses both alike.
				assert.Equal(t, http.StatusTooManyRequests, owner[c.attempts-1].Code)
				return
			}
			for i, w := range owner {
				assert.Equal(t, http.StatusUnauthorized, w.Code, "attempt %d: only the password is wrong", i+1)
			}
			// The owner can still log in.
			assert.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.230:1", "owner@example.com", "pw12345678").Code)
		})
	}
}

// The bound is exact: logins whose hashes run at the same time have all
// passed the check before the hash, but each is recorded right after its
// password matched and before its session is created, so only as many get
// a session as the limit has room for. The others get the limit's 429.
func TestLoginsPerAccountIsExactForLoginsInFlight(t *testing.T) {
	const limit, parallel = 3, 4
	s := newStack(t, withAudit, func(o *Options, _ *stack) { o.LoginsPerAccount = limit })
	const email, password = "exact@example.com", holdPrefix + "pw-12345"
	uid := s.createUser(t, email, password)
	for i := 0; i < limit-1; i++ {
		require.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.244:1", email, password).Code)
	}
	lim := limitersOf(t, s.h)
	key := accountKey(email)
	require.Equal(t, limit-1, lim.logins.count(key), "one place left")
	sessionsBefore := s.sessionsOf(t, uid)
	successesBefore := s.auditCount(t, "auth.login.success")

	// parallel correct-password logins from as many addresses, all parked
	// inside their hashes: every one of them has passed the check.
	hold := holdHashes(t)
	var reqs []*http.Request
	for i := 0; i < parallel; i++ {
		reqs = append(reqs, newFormPost(t, s.h, nil, "/login",
			url.Values{"email": {email}, "password": {password}}, fmt.Sprintf("198.51.100.%d:1", 245+i)))
	}
	answers := serveAll(s.h, reqs)
	hold.waitEntered(t, parallel)
	hold.releaseAll()

	codes := map[int]int{}
	for i := 0; i < parallel; i++ {
		w := <-answers
		codes[w.Code]++
		if w.Code == http.StatusTooManyRequests {
			assert.Contains(t, w.Body.String(), msgTooManyLoginsAccount)
			assert.Positive(t, retryAfterSeconds(t, w))
			assert.Nil(t, findCookie(w, "tunneld_session"), "no session for a refused login")
		}
	}
	assert.Equal(t, map[int]int{http.StatusSeeOther: 1, http.StatusTooManyRequests: parallel - 1}, codes)
	assert.Equal(t, sessionsBefore+1, s.sessionsOf(t, uid), "exactly one session row")
	assert.Equal(t, successesBefore+1, s.auditCount(t, "auth.login.success"), "exactly one audit row")
	assert.Equal(t, limit, lim.logins.count(key), "the count is at the limit")
	assert.Zero(t, lim.loginAccount.count(key), "the refused logins gave their failure places back")
}

// A wrong password in flight holds no place in the count: the check before
// the hash only looks, and only a successful login is counted, after the
// session was stored. Otherwise the outsider's attempts in flight could
// keep the owner out.
func TestLoginsPerAccountWrongPasswordsInFlightHoldNoPlace(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) { o.LoginsPerAccount = 2 })
	s.createUser(t, "in-flight@example.com", "pw12345678")
	require.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.240:1", "in-flight@example.com", "pw12345678").Code)

	hold := holdHashes(t)
	outsider := newFormPost(t, s.h, nil, "/login",
		url.Values{"email": {"in-flight@example.com"}, "password": {holdPrefix + "wrong"}}, "198.51.100.241:1")
	parked := serveAll(s.h, []*http.Request{outsider})
	hold.waitEntered(t, 1)

	// The outsider's wrong password is in its hash: the owner's second
	// login, the last the limit allows, goes through.
	require.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.242:1", "in-flight@example.com", "pw12345678").Code)
	hold.releaseAll()
	assert.Equal(t, http.StatusUnauthorized, (<-parked).Code)
	assert.Equal(t, 2, limitersOf(t, s.h).logins.count(accountKey("in-flight@example.com")))

	w := s.login(t, "198.51.100.242:1", "in-flight@example.com", "pw12345678")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), msgTooManyLoginsAccount)
}

func TestLoginsPerAccountGiveBackUndecidedLogins(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) { o.LoginsPerAccount = 1 })
	s.createUser(t, "undecided@example.com", "pw12345678")

	// No hash slot: the login cannot be decided and does not count.
	useHashLimits(t, auth.HashLimits{MaxConcurrent: 1, MaxWait: 50 * time.Millisecond})
	hold := holdHashes(t)
	parked := make(chan struct{})
	go func() {
		defer close(parked)
		_, _ = auth.HashPasswordContext(context.Background(), holdPrefix+"the-only-slot")
	}()
	hold.waitEntered(t, 1)
	require.Equal(t, http.StatusServiceUnavailable, s.login(t, "198.51.100.185:1", "undecided@example.com", "pw12345678").Code)
	assert.Zero(t, limitersOf(t, s.h).logins.count(accountKey("undecided@example.com")))
	hold.releaseAll()
	<-parked // its hash has given the only slot back

	require.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.185:1", "undecided@example.com", "pw12345678").Code)
	require.Equal(t, http.StatusTooManyRequests, s.login(t, "198.51.100.185:1", "undecided@example.com", "pw12345678").Code)
}

// failInserts makes every INSERT on table fail until the test ends. The
// trigger name starts with dbtest_fail_delete_ so that dbtest.Pool removes
// it should the test be killed before its cleanup.
func failInserts(t *testing.T, s *stack, table string) {
	t.Helper()
	ctx := context.Background()
	fn, trg := "logins_test_fail_"+table, "dbtest_fail_delete_logins_"+table
	_, err := s.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION `+fn+`() RETURNS trigger LANGUAGE plpgsql AS
		$$ BEGIN RAISE EXCEPTION 'injected failure'; END $$`)
	require.NoError(t, err)
	_, err = s.pool.Exec(ctx, `CREATE TRIGGER `+trg+` BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION `+fn+`()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = s.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+trg+` ON `+table)
		_, _ = s.pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+fn+`()`)
	})
}

func TestLoginsPerAccountGiveBackALoginWithoutSession(t *testing.T) {
	s := newStack(t, func(o *Options, _ *stack) { o.LoginsPerAccount = 1 })
	s.createUser(t, "no-session@example.com", "pw12345678")

	// The password is right, but the session cannot be stored: no session
	// row, no audit row, and the login does not count.
	failInserts(t, s, "sessions")
	w := s.login(t, "198.51.100.186:1", "no-session@example.com", "pw12345678")
	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Zero(t, limitersOf(t, s.h).logins.count(accountKey("no-session@example.com")))
}

func TestLoginsPerAccountOptions(t *testing.T) {
	rl := newRateLimiters(Options{})
	assert.Equal(t, 30, rl.logins.limit, "default")
	assert.Equal(t, 15*time.Minute, rl.logins.window, "the login window")
	rl = newRateLimiters(Options{LoginsPerAccount: 7, LoginFailureWindow: time.Minute})
	assert.Equal(t, 7, rl.logins.limit)
	assert.Equal(t, time.Minute, rl.logins.window)
	assert.LessOrEqual(t, newRateLimiters(Options{LoginsPerAccount: -1}).logins.limit, 0, "negative disables")
}
