package frontend

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock is a clock that only moves when the test says so.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestRateLimiter(t *testing.T) {
	t.Run("allows limit events in a window and refuses the next", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(3, time.Hour, 0, clock.Now)
		for i := 0; i < 3; i++ {
			_, _, ok := l.take("k")
			require.True(t, ok, "event %d", i+1)
			clock.Advance(time.Minute)
		}
		_, retry, ok := l.take("k")
		require.False(t, ok, "the fourth event in the hour")
		// The first event was 3 minutes ago; it leaves the window in 57.
		assert.Equal(t, 57*time.Minute, retry)
	})
	t.Run("the window slides", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(2, time.Hour, 0, clock.Now)
		_, _, ok := l.take("k") // t=0
		require.True(t, ok)
		clock.Advance(30 * time.Minute)
		_, _, ok = l.take("k") // t=30m
		require.True(t, ok)
		clock.Advance(29 * time.Minute)
		_, _, ok = l.take("k") // t=59m: both still in the window
		require.False(t, ok)
		clock.Advance(time.Minute)
		_, _, ok = l.take("k") // t=60m: the first left the window
		require.True(t, ok)
		_, _, ok = l.take("k") // the one from t=30m is still in
		require.False(t, ok)
	})
	t.Run("a refused event is not recorded", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(1, time.Hour, 0, clock.Now)
		_, _, ok := l.take("k")
		require.True(t, ok)
		for i := 0; i < 5; i++ {
			clock.Advance(10 * time.Minute)
			_, _, ok = l.take("k")
			require.False(t, ok)
		}
		clock.Advance(10*time.Minute + time.Nanosecond) // one hour after the only recorded event
		_, _, ok = l.take("k")
		require.True(t, ok, "refusals must not extend the block")
	})
	t.Run("giveBack returns an event", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(2, time.Hour, 0, clock.Now)
		s1, _, ok := l.take("k")
		require.True(t, ok)
		clock.Advance(time.Second)
		_, _, ok = l.take("k")
		require.True(t, ok)
		l.giveBack("k", s1)
		_, _, ok = l.take("k")
		require.True(t, ok, "the given-back event no longer counts")
		_, _, ok = l.take("k")
		require.False(t, ok)
		// Giving back something that is not there changes nothing.
		l.giveBack("k", clock.Now().Add(-time.Hour))
		l.giveBack("other", clock.Now())
		_, _, ok = l.take("k")
		require.False(t, ok)
	})
	t.Run("keys are independent", func(t *testing.T) {
		l := newRateLimiter(1, time.Hour, 0, newFakeClock().Now)
		_, _, ok := l.take("a")
		require.True(t, ok)
		_, _, ok = l.take("b")
		require.True(t, ok)
		_, _, ok = l.take("a")
		require.False(t, ok)
	})
	t.Run("a limit of zero or less never refuses and keeps no state", func(t *testing.T) {
		l := newRateLimiter(0, time.Hour, 0, newFakeClock().Now)
		for i := 0; i < 100; i++ {
			_, _, ok := l.take(fmt.Sprint(i % 3))
			require.True(t, ok)
		}
		assert.Equal(t, 0, l.size())
	})
	t.Run("state that left the window is pruned", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(5, time.Hour, 0, clock.Now)
		for i := 0; i < 1000; i++ {
			_, _, ok := l.take(fmt.Sprintf("client-%d", i))
			require.True(t, ok)
		}
		require.Equal(t, 1000, l.size())
		clock.Advance(time.Hour + time.Minute)
		_, _, ok := l.take("late")
		require.True(t, ok)
		assert.Equal(t, 1, l.size(), "keys whose events all left the window are dropped")
	})
	t.Run("a full table admits a new key by evicting the least recently counted one", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(2, time.Hour, 3, clock.Now)
		for _, k := range []string{"a", "b", "c"} {
			_, _, ok := l.take(k)
			require.True(t, ok)
			clock.Advance(time.Second)
		}
		_, _, ok := l.take("a") // a is now the most recently counted key
		require.True(t, ok)
		clock.Advance(time.Second)

		_, _, ok = l.take("d")
		require.True(t, ok, "a new key is admitted although the table is full")
		assert.Equal(t, 3, l.size())
		assert.Zero(t, l.count("b"), "b was counted least recently: evicted")
		assert.Equal(t, 1, l.count("c"))
		assert.Equal(t, 2, l.count("a"))
		assert.Equal(t, 1, l.count("d"))

		// Keys that stayed keep their limits.
		_, _, ok = l.take("a")
		require.False(t, ok, "a is still at its limit")

		// The next new key evicts the next one in line (c).
		_, _, ok = l.take("e")
		require.True(t, ok)
		assert.Zero(t, l.count("c"))
		assert.Equal(t, 2, l.count("a"))
		assert.Equal(t, 3, l.size())
	})
	t.Run("a refused event does not move its key in the eviction order", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(1, time.Hour, 2, clock.Now)
		_, _, ok := l.take("a")
		require.True(t, ok)
		clock.Advance(time.Second)
		_, _, ok = l.take("b")
		require.True(t, ok)
		clock.Advance(time.Second)
		_, _, ok = l.take("a") // refused, a stays the oldest
		require.False(t, ok)
		_, _, ok = l.take("c")
		require.True(t, ok)
		assert.Zero(t, l.count("a"))
		assert.Equal(t, 1, l.count("b"))
	})
	t.Run("the failure table pushes out entries with fewer failures first", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(3, time.Hour, 4, clock.Now).evictingByFailures("test table")
		for i := 0; i < 3; i++ {
			require.True(t, failOnce(l, "v")) // v at its limit: credit for 2 more passes
		}
		// One new key with one failure each: never refused. v survives
		// while it has credit; each pass of the list costs 3 new keys (the
		// other entries of the full table) once it is full, so v goes with
		// the 10th: three to fill the table, then three per pass.
		for i := 1; i <= 10; i++ {
			require.True(t, failOnce(l, fmt.Sprintf("x%d", i)), "a new key is never refused")
			assert.LessOrEqual(t, l.size(), 4)
			if i < 10 {
				assert.Equal(t, 3, l.count("v"), "v survives new key %d", i)
				_, _, ok := l.take("v")
				require.False(t, ok, "v stays at its limit")
			}
		}
		assert.Zero(t, l.count("v"), "after 3 passes v is pushed out")
	})
	t.Run("the failure table never refuses a new key, also when every entry is at its limit", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(2, time.Hour, 3, clock.Now).evictingByFailures("test table")
		for _, k := range []string{"a", "b", "c"} {
			for i := 0; i < 2; i++ {
				require.True(t, failOnce(l, k))
			}
		}
		require.True(t, failOnce(l, "d"))
		assert.Equal(t, 3, l.size())
		assert.Equal(t, 1, l.count("d"))
	})
	t.Run("the failure table drops expired entries before it pushes out a live one", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(3, time.Hour, 3, clock.Now).evictingByFailures("test table")
		require.True(t, failOnce(l, "old"))
		clock.Advance(50 * time.Minute)
		for _, k := range []string{"a", "b"} {
			require.True(t, failOnce(l, k))
		}
		clock.Advance(11 * time.Minute) // old has left the window
		require.True(t, failOnce(l, "new"))
		assert.Zero(t, l.count("old"))
		assert.Equal(t, 1, l.count("a"), "the live entries stay")
		assert.Equal(t, 1, l.count("b"))
	})
	t.Run("a check and a refused take change nothing in the failure table", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(3, time.Hour, 3, clock.Now).evictingByFailures("test table")
		for i := 0; i < 3; i++ {
			require.True(t, failOnce(l, "v"))
			clock.Advance(20 * time.Minute)
		}
		for i := 0; i < 3; i++ {
			require.True(t, failOnce(l, "b")) // b at its limit
		}
		// 61 minutes after v's first failure it has left the window; v's
		// entry is still at the front.
		clock.Advance(time.Minute)
		before := failureTableState(l)
		_, ok := l.check("v")
		require.True(t, ok, "two live failures of three")
		_, _, ok = l.take("b")
		require.False(t, ok)
		assert.Equal(t, before, failureTableState(l))
	})
	t.Run("a confirmed failure drops the failures that left the window, and their credit", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(5, time.Hour, 3, clock.Now).evictingByFailures("test table")
		for i := 0; i < 3; i++ {
			require.True(t, failOnce(l, "v"))
			clock.Advance(time.Minute)
		}
		clock.Advance(60 * time.Minute) // all three have left the window
		require.True(t, failOnce(l, "v"))
		e := l.entries["v"]
		require.Len(t, e.events, 1)
		assert.Zero(t, e.credit)
	})
	t.Run("a take that is given back changes nothing, for an existing and for a new key", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(5, time.Hour, 3, clock.Now).evictingByFailures("test table")
		for _, k := range []string{"a", "b"} {
			require.True(t, failOnce(l, k))
		}
		for i := 0; i < 3; i++ {
			require.True(t, failOnce(l, "v"))
		}
		before := failureTableState(l)
		// A login of an existing key in flight: it holds a place against
		// the key's limit, nothing else.
		stamp, _, ok := l.take("a")
		require.True(t, ok)
		assert.Equal(t, 2, l.count("a"), "the place in flight counts against a's limit")
		assert.Equal(t, before, failureTableState(l), "in flight: no move, no credit")
		// A login of a new key in flight while the table is full: no room
		// is made for it.
		newStamp, _, ok := l.take("new")
		require.True(t, ok)
		assert.Equal(t, before, failureTableState(l), "in flight: nothing pushed out")
		l.giveBack("a", stamp)
		l.giveBack("new", newStamp)
		assert.Equal(t, before, failureTableState(l))
		assert.Equal(t, 1, l.count("a"))
		assert.Zero(t, l.count("new"))
		assert.Equal(t, 3, l.size())
	})
	t.Run("a confirmed failure gives credit and does not move its entry", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(5, time.Hour, 3, clock.Now).evictingByFailures("test table")
		for _, k := range []string{"a", "b", "c"} {
			require.True(t, failOnce(l, k))
		}
		require.True(t, failOnce(l, "a"))
		st := failureTableState(l)
		require.Len(t, st, 3)
		assert.Equal(t, "a", st[0].key, "a stays at the front")
		assert.Equal(t, 1, st[0].credit)
	})
	t.Run("pending places count against the key's limit", func(t *testing.T) {
		l := newRateLimiter(2, time.Hour, 3, newFakeClock().Now).evictingByFailures("test table")
		for i := 0; i < 2; i++ {
			_, _, ok := l.take("k")
			require.True(t, ok)
		}
		_, retry, ok := l.take("k")
		require.False(t, ok, "two attempts in flight hold the limit of two")
		assert.Equal(t, time.Hour, retry)
	})
	t.Run("check looks without counting", func(t *testing.T) {
		clock := newFakeClock()
		l := newRateLimiter(2, time.Hour, 0, clock.Now)
		for i := 0; i < 5; i++ {
			_, ok := l.check("k")
			require.True(t, ok)
		}
		assert.Zero(t, l.count("k"), "a check records nothing")
		assert.Zero(t, l.size(), "and keeps no state for a new key")

		_, _, ok := l.take("k")
		require.True(t, ok)
		clock.Advance(10 * time.Minute)
		_, _, ok = l.take("k")
		require.True(t, ok)
		retry, ok := l.check("k")
		require.False(t, ok, "at the limit")
		assert.Equal(t, 50*time.Minute, retry, "until the oldest event leaves the window")
		assert.Equal(t, 2, l.count("k"))

		clock.Advance(50 * time.Minute)
		_, ok = l.check("k")
		assert.True(t, ok, "the oldest event has left the window")
		assert.Equal(t, 1, l.count("k"))

		_, ok = newRateLimiter(0, time.Hour, 0, clock.Now).check("k")
		assert.True(t, ok, "no limit")
	})
}

func TestRateLimiterUnderConcurrency(t *testing.T) {
	const limit, goroutines = 10, 200
	l := newRateLimiter(limit, time.Hour, 0, time.Now)

	// Many takes on one key at once: exactly limit are admitted.
	var admitted atomic.Int32
	stamps := make(chan time.Time, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if stamp, _, ok := l.take("k"); ok {
				admitted.Add(1)
				stamps <- stamp
			}
		}()
	}
	wg.Wait()
	close(stamps)
	require.EqualValues(t, limit, admitted.Load())
	require.Equal(t, limit, l.count("k"))

	// Giving them all back at once leaves nothing.
	for stamp := range stamps {
		wg.Add(1)
		go func(s time.Time) {
			defer wg.Done()
			l.giveBack("k", s)
		}(stamp)
	}
	wg.Wait()
	require.Equal(t, 0, l.count("k"))
	require.Equal(t, 0, l.size())

	// Take and give back in a loop: never more than limit held at once,
	// and the count is back at zero at the end.
	var held, maxHeld atomic.Int32
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				stamp, _, ok := l.take("k")
				if !ok {
					continue
				}
				n := held.Add(1)
				for {
					m := maxHeld.Load()
					if n <= m || maxHeld.CompareAndSwap(m, n) {
						break
					}
				}
				held.Add(-1)
				l.giveBack("k", stamp)
			}
		}()
	}
	wg.Wait()
	assert.LessOrEqual(t, maxHeld.Load(), int32(limit))
	assert.Equal(t, 0, l.count("k"))
	assert.Equal(t, 0, l.size())
}

func TestRateLimitersFromOptions(t *testing.T) {
	type got struct {
		limit  int
		window time.Duration
	}
	read := func(l *rateLimiter) got { return got{l.limit, l.window} }

	t.Run("zero values select the defaults", func(t *testing.T) {
		rl := newRateLimiters(Options{})
		assert.Equal(t, got{10, 15 * time.Minute}, read(rl.loginAccount))
		assert.Equal(t, got{30, 15 * time.Minute}, read(rl.loginIP))
		assert.Equal(t, got{5, time.Hour}, read(rl.signupIP))
		assert.Equal(t, got{3, time.Hour}, read(rl.resetIP))
		assert.Equal(t, got{3, time.Hour}, read(rl.resetAccount))
		assert.Equal(t, got{3, time.Hour}, read(rl.resetStored))
		for _, l := range []*rateLimiter{rl.loginAccount, rl.loginIP, rl.signupIP, rl.resetIP, rl.resetAccount, rl.resetStored, rl.resend} {
			assert.Equal(t, DefaultRateLimitMaxKeys, l.maxKeys)
		}
		assert.Equal(t, int64(64<<10), Options{}.maxRequestBodyBytes())
	})
	t.Run("only the per-account failure table evicts by failures", func(t *testing.T) {
		rl := newRateLimiters(Options{})
		assert.True(t, rl.loginAccount.evictByFailures, "a flood must not cheaply push a locked account out")
		for _, l := range rl.tables() {
			if l != rl.loginAccount {
				assert.False(t, l.evictByFailures, "the other tables evict their oldest entry")
			}
		}
	})
	t.Run("set values are used", func(t *testing.T) {
		rl := newRateLimiters(Options{
			LoginFailuresPerAccount: 4, LoginFailuresPerIP: 7, LoginFailureWindow: time.Minute,
			SignupsPerIP: 2, SignupWindow: 2 * time.Minute,
			ResetRequestsPerIP: 5, ResetRequestsPerAccount: 6, ResetRequestWindow: 3 * time.Minute,
			RateLimitMaxKeys: 9,
		})
		assert.Equal(t, got{4, time.Minute}, read(rl.loginAccount))
		assert.Equal(t, got{7, time.Minute}, read(rl.loginIP))
		assert.Equal(t, got{2, 2 * time.Minute}, read(rl.signupIP))
		assert.Equal(t, got{5, 3 * time.Minute}, read(rl.resetIP))
		assert.Equal(t, got{6, 3 * time.Minute}, read(rl.resetAccount))
		assert.Equal(t, got{6, 3 * time.Minute}, read(rl.resetStored))
		assert.Equal(t, 9, rl.loginIP.maxKeys)
		assert.Equal(t, int64(100), Options{MaxRequestBodyBytes: 100}.maxRequestBodyBytes())
	})
	t.Run("negative values disable", func(t *testing.T) {
		rl := newRateLimiters(Options{
			LoginFailuresPerAccount: -1, LoginFailuresPerIP: -1, SignupsPerIP: -1,
			ResetRequestsPerIP: -1, ResetRequestsPerAccount: -1, RateLimitMaxKeys: -1,
			LoginFailureWindow: -time.Minute,
		})
		for _, l := range []*rateLimiter{rl.loginAccount, rl.loginIP, rl.signupIP, rl.resetIP, rl.resetAccount} {
			assert.LessOrEqual(t, l.limit, 0)
		}
		assert.LessOrEqual(t, rl.loginIP.maxKeys, 0)
		assert.Equal(t, 15*time.Minute, rl.loginIP.window, "a negative window selects the default")
		assert.LessOrEqual(t, Options{MaxRequestBodyBytes: -1}.maxRequestBodyBytes(), int64(0))
	})
}

func TestClientIPComesFromTheConnection(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:4711"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	r.Header.Set("X-Real-IP", "198.51.100.2")
	r.Header.Set("True-Client-IP", "198.51.100.3")
	r.Header.Set("Forwarded", "for=198.51.100.4")
	assert.Equal(t, netip.MustParseAddr("203.0.113.7"), clientIP(r))

	r.RemoteAddr = "[::ffff:192.0.2.9]:443"
	assert.Equal(t, netip.MustParseAddr("192.0.2.9"), clientIP(r), "an IPv4 peer on a dual-stack listener")

	r.RemoteAddr = "garbage"
	assert.False(t, clientIP(r).IsValid())
}

func TestSourceKeyGroupsIPv6By64(t *testing.T) {
	key := func(s string) string { return sourceKey(netip.MustParseAddr(s)) }
	assert.Equal(t, key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff:ffff:ffff:ffff"))
	assert.NotEqual(t, key("2001:db8:1:2::1"), key("2001:db8:1:3::1"))
	assert.NotEqual(t, key("192.0.2.1"), key("192.0.2.2"), "IPv4 addresses stand for themselves")
	assert.Equal(t, key("fe80::1%eth0"), key("fe80::2"), "a zone does not split the bucket")
	assert.Equal(t, sourceKey(netip.Addr{}), sourceKey(netip.Addr{}), "unparsable peers share one bucket")
	assert.NotEqual(t, sourceKey(netip.Addr{}), key("192.0.2.1"))
}

func TestAccountKeyIgnoresCaseAndSpace(t *testing.T) {
	assert.Equal(t, accountKey("user@example.com"), accountKey("  User@Example.COM "))
	assert.NotEqual(t, accountKey("user@example.com"), accountKey("other@example.com"))
	assert.NotContains(t, accountKey("user@example.com"), "user", "the key does not keep the address")
}

// failOnce counts one final failure for key in a table that evicts by
// failures: a take that is confirmed. It reports whether the take was
// admitted.
func failOnce(l *rateLimiter, key string) bool {
	stamp, _, ok := l.take(key)
	if ok {
		l.confirm(key, stamp)
	}
	return ok
}

// tableEntryState is what a key's entry in the clock of a failure table
// is: its counted events and its credit (pending events are left out).
type tableEntryState struct {
	key    string
	events []time.Time
	credit int
}

// failureTableState lists the entries of the clock, front first.
func failureTableState(l *rateLimiter) []tableEntryState {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []tableEntryState
	for el := l.order.Front(); el != nil; el = el.Next() {
		e := el.Value.(*rlEntry)
		out = append(out, tableEntryState{key: e.key, events: append([]time.Time(nil), e.events...), credit: e.credit})
	}
	return out
}

// liveTableState keeps the entries with a failure still inside the window.
func liveTableState(s []tableEntryState, now time.Time, window time.Duration) []tableEntryState {
	var out []tableEntryState
	for _, e := range s {
		if now.Sub(e.events[len(e.events)-1]) < window {
			out = append(out, e)
		}
	}
	return out
}

// failureTableAttack is the result of one attack on the victim keys of a
// failure table: the confirmed (counted) failures per key, the attempts that
// were given back (free; worth nothing to the attacker's bill), and per
// victim the extra guesses it bought (live failures of the victim that the
// table lost; no time passes, so none left by time).
type failureTableAttack struct {
	counted map[string]int
	extra   map[string]int
	free    int
}

// countedBesides is the number of counted failures of every key but v.
func (a failureTableAttack) countedBesides(v string) int {
	n := 0
	for k, c := range a.counted {
		if k != v {
			n += c
		}
	}
	return n
}

// playFailureTableAttack plays a strategy against the victim keys of a
// table of maxKeys keys and limit failures per key, for rounds rounds. The
// table starts full (maxKeys keys with one counted failure each), so every
// victim comes into a full table. Each round guesses a victim up to c
// failures and then tries to push it out:
//   - "flood": one counted new key per try.
//   - "wall": first raise every other place to h failures, then flood.
//   - "raised": every new key gets h counted failures.
//   - "rotate": before each counted new key, a free attempt (take, given
//     back) for every entry in front of the victim.
//   - "free-new": free attempts for new keys against the full table, then
//     one counted new key.
//   - "overlap": attempts in flight for every entry in front of the victim
//     and for new keys at once; one counted new key confirmed while they
//     are in flight; then they are given back.
//   - "successes": a wall, and successful logins (free) of wall keys
//     between the counted new keys.
//   - "two-victims": two victims guessed in turn; a guess at the one that
//     is out of the table puts it back and makes room, which can push out
//     the other.
//   - "many-victims": maxKeys/2 victims, all guessed up to c, then pushed
//     out together: the looks are shared by all of them.
//   - "ahead": a counted failure of the front-most entry ahead of the
//     victim that has room below its limit (a new key when none has): it
//     must not move that entry behind the victim.
func playFailureTableAttack(t *testing.T, maxKeys, limit int, strategy string, c, h, rounds int) failureTableAttack {
	t.Helper()
	l := newRateLimiter(limit, time.Hour, maxKeys, newFakeClock().Now).evictingByFailures("simulation")
	res := failureTableAttack{counted: map[string]int{}, extra: map[string]int{}}
	fail := func(key string) {
		require.True(t, failOnce(l, key), "%s: a key below its limit is never refused", key)
		res.counted[key]++
	}
	free := func(key string) {
		if stamp, _, ok := l.take(key); ok {
			l.giveBack(key, stamp)
			res.free++
		}
	}
	keysAhead := func(victim string) []string {
		var out []string
		for _, e := range failureTableState(l) {
			if e.key == victim {
				break
			}
			out = append(out, e.key)
		}
		return out
	}
	n := 0
	newKey := func() string { n++; return fmt.Sprintf("junk-%d", n) }
	for i := 0; i < maxKeys; i++ {
		fail(fmt.Sprintf("background-%d", i))
	}
	if strategy == "wall" || strategy == "successes" {
		for i := 0; i < maxKeys-1; i++ {
			for j := 0; j < h; j++ {
				fail(fmt.Sprintf("wall-%d", i))
			}
		}
	}
	victims := []string{"v"}
	switch strategy {
	case "two-victims":
		victims = []string{"v1", "v2"}
	case "many-victims":
		victims = nil
		for i := 0; i < maxKeys/2; i++ {
			victims = append(victims, fmt.Sprintf("v%d", i))
		}
	}
	for r := 0; r < rounds; r++ {
		group := []string{victims[r%len(victims)]}
		if strategy == "many-victims" {
			group = victims
		}
		before := map[string]int{}
		for _, v := range group {
			for l.count(v) < c {
				fail(v)
			}
			before[v] = l.count(v)
		}
		v := group[0]
		for tries := 0; l.count(v) > 0; tries++ {
			require.Less(t, tries, 100*maxKeys*limit, "the attack does not end")
			switch strategy {
			case "rotate":
				for _, key := range keysAhead(v) {
					free(key)
				}
				fail(newKey())
			case "free-new":
				for i := 0; i < maxKeys; i++ {
					free(newKey())
				}
				fail(newKey())
			case "overlap":
				type inFlight struct {
					key   string
					stamp time.Time
				}
				var held []inFlight
				for _, key := range append(keysAhead(v), newKey(), newKey()) {
					if stamp, _, ok := l.take(key); ok {
						held = append(held, inFlight{key, stamp})
					}
				}
				fail(newKey())
				for _, f := range held {
					l.giveBack(f.key, f.stamp)
					res.free++
				}
			case "raised":
				key := newKey()
				for j := 0; j < h && l.count(v) > 0; j++ {
					fail(key)
				}
			case "successes":
				fail(newKey())
				free(fmt.Sprintf("wall-%d", n%(maxKeys-1)))
			case "ahead":
				key := ""
				for _, e := range failureTableState(l) {
					if e.key == v {
						break
					}
					if l.count(e.key) < limit {
						key = e.key
						break
					}
				}
				if key == "" {
					key = newKey()
				}
				fail(key)
			case "two-victims":
				// The other victim's guesses as new keys do the work.
				if other := victims[(r+1)%len(victims)]; l.count(other) == 0 {
					fail(other)
				} else {
					fail(newKey())
				}
			default: // flood, wall, many-victims
				fail(newKey())
			}
		}
		for _, w := range group {
			if l.count(w) == 0 {
				res.extra[w] += before[w]
			}
		}
	}
	return res
}

// The price of an extra guess at an account, in counted failed logins. For
// one victim key of the table of failed logins per account: to push out its
// entry while it holds e live failures, the entry must reach the front of the
// clock e times; it came in at the back of a full table, and after each skip
// it is at the back again, so every arrival needs maxKeys-1 advances. Here no
// time passes, so only a look advances it (an entry ahead removed, or skipped
// to the back; with time, expired entries leaving count the same way), and
// each look uses up a unit paid by one confirmed failure of another key: the
// first failure of the entry that is removed, or the failure that gave the
// credit that is used. So the counted failures of the other keys are at least
// e·(maxKeys-1) — the same units serve every victim behind them, so the bound
// is per account. Attempts that are given back (successful logins, logins the
// server could not decide, clients that went away) are free for the attacker
// and must buy nothing.
func TestLoginFailureTablePriceOfAGuess(t *testing.T) {
	const limit, rounds = 10, 4
	strategies := []string{"flood", "wall", "raised", "rotate", "free-new", "overlap", "successes", "two-victims", "many-victims", "ahead"}
	for _, maxKeys := range []int{8, 30} {
		for c := 1; c <= limit; c++ {
			for _, s := range strategies {
				heights := []int{1}
				if s == "wall" || s == "raised" || s == "successes" {
					heights = []int{2, 3, 5, limit}
				}
				for _, h := range heights {
					res := playFailureTableAttack(t, maxKeys, limit, s, c, h, rounds)
					require.NotEmpty(t, res.extra, "%s: the attack pushed out a victim", s)
					for v, extra := range res.extra {
						assert.GreaterOrEqual(t, res.countedBesides(v), extra*(maxKeys-1),
							"%d keys, victim kept at %d, %s (h=%d): %d counted failures of other keys (and %d free attempts) bought %d extra guesses at %s",
							maxKeys, c, s, h, res.countedBesides(v), res.free, extra, v)
					}
				}
			}
		}
	}
}

// The model check, written from the requirement rather than from the code:
// a request that is not counted when it ends must leave the failure table
// as if it had never been made. Random scripts of attempts (taken, then
// confirmed or given back, overlapping), refusals and clock steps are played
// twice — in full, and without every attempt that was given back or refused
// — and after every step the two tables must hold the same live entries (a
// failure inside the window) in the same order with the same counted events
// and credit. (An entry whose failures have all left the window is gone for
// every purpose; when the front of the clock is pruned of such entries
// depends on when the next request comes, so they are left out.) On the
// way: a key below its limit (attempts in flight included) is never
// refused, and the table never holds more than maxKeys entries.
func TestLoginFailureTableModelCheck(t *testing.T) {
	const limit, maxKeys, keys = 4, 5, 12
	window := time.Hour
	for seed := int64(1); seed <= 40; seed++ {
		rng := rand.New(rand.NewSource(seed))
		clock := newFakeClock()
		full := newRateLimiter(limit, window, maxKeys, clock.Now).evictingByFailures("model")
		counted := newRateLimiter(limit, window, maxKeys, clock.Now).evictingByFailures("model")
		type attempt struct {
			key          string
			stamp        time.Time // in full
			countedStamp time.Time // in counted, if the attempt will be confirmed
			confirm      bool
		}
		var inFlight []attempt
		for step := 0; step < 2000; step++ {
			switch op := rng.Intn(10); {
			case op < 5:
				key := fmt.Sprintf("k%d", rng.Intn(keys))
				a := attempt{key: key, confirm: rng.Intn(2) == 0}
				live := full.count(key)
				stamp, _, ok := full.take(key)
				if !ok {
					require.GreaterOrEqual(t, live, limit, "seed %d step %d: %s refused below its limit", seed, step, key)
					break // a refused attempt is not in either history
				}
				a.stamp = stamp
				if a.confirm {
					cs, _, cok := counted.take(key)
					require.True(t, cok, "seed %d step %d: the history without free attempts refused %s", seed, step, key)
					a.countedStamp = cs
				}
				inFlight = append(inFlight, a)
			case op < 9 && len(inFlight) > 0:
				i := rng.Intn(len(inFlight))
				a := inFlight[i]
				inFlight = append(inFlight[:i], inFlight[i+1:]...)
				if a.confirm {
					full.confirm(a.key, a.stamp)
					counted.confirm(a.key, a.countedStamp)
				} else {
					full.giveBack(a.key, a.stamp)
				}
			default:
				clock.Advance(time.Duration(rng.Intn(20)) * time.Minute)
			}
			now := clock.Now()
			got := liveTableState(failureTableState(full), now, window)
			require.Equal(t, liveTableState(failureTableState(counted), now, window), got,
				"seed %d step %d: free attempts changed the table", seed, step)
			require.LessOrEqual(t, len(failureTableState(full)), maxKeys)
			for _, e := range got {
				require.GreaterOrEqual(t, e.credit, 0)
				require.LessOrEqual(t, e.credit, len(e.events)-1, "seed %d step %d: credit of %s", seed, step, e.key)
			}
		}
	}
}

// The work to make room does not grow with the table: every look at an
// entry either removes it or uses up one credit, and a confirmed failure
// gives at most one credit, so a table of 100 and one of 10000 keys need the
// same number of looks per request for the same attack (the table full of
// entries at their limit, then a flood of new keys several times its size).
func TestLoginFailureTableCostIsIndependentOfSize(t *testing.T) {
	perRequest := map[int]float64{}
	for _, size := range []int{100, 10000} {
		l := newRateLimiter(10, time.Hour, size, newFakeClock().Now).evictingByFailures("cost")
		takes := 0
		fail := func(key string) {
			require.True(t, failOnce(l, key))
			takes++
		}
		for i := 0; i < size; i++ {
			for j := 0; j < 10; j++ {
				fail(fmt.Sprintf("full-%d", i))
			}
		}
		for i := 0; i < 5*size; i++ {
			fail(fmt.Sprintf("new-%d", i))
		}
		assert.LessOrEqual(t, l.inspections, 2*takes, "%d keys", size)
		perRequest[size] = float64(l.inspections) / float64(takes)
	}
	assert.InDelta(t, perRequest[100], perRequest[10000], 0.01, "looks per request: %v", perRequest)
}
