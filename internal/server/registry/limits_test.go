package registry

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
)

// testSession is a session with an owner, a token and a Close counter.
type testSession struct {
	id      string
	userID  int64
	tokenID int64
	closes  atomic.Int32
}

func (s *testSession) ID() string          { return s.id }
func (s *testSession) UserIDValue() int64  { return s.userID }
func (s *testSession) TokenIDValue() int64 { return s.tokenID }
func (s *testSession) Close() error        { s.closes.Add(1); return nil }
func (s *testSession) closed() bool        { return s.closes.Load() > 0 }

func sess(id string, userID, tokenID int64) *testSession {
	return &testSession{id: id, userID: userID, tokenID: tokenID}
}

// snapshotKeys renders SnapshotAll as sorted "type:session:subdomain:port".
func snapshotKeys(r *Registry) []string {
	var out []string
	for _, e := range r.SnapshotAll() {
		out = append(out, fmt.Sprintf("%s:%s:%s:%d", e.Type, e.SessionID, e.Subdomain, e.Port))
	}
	sort.Strings(out)
	return out
}

// ---- RegisterHTTP: second line of defence for names ----

func TestRegisterHTTPAcceptsWellFormedNames(t *testing.T) {
	r := New()
	names := []string{"abc", "myapp", "victim", "fragapp", "notmine", "other-app", "e2eapp", "x1y2z3", strings.Repeat("a", 63)}
	for i, name := range names {
		s := sess(fmt.Sprintf("s%d", i), 1, 0)
		require.NoError(t, r.RegisterHTTP(name, s), "name %q", name)
		got, ok := r.LookupHTTP(name)
		require.True(t, ok, "name %q", name)
		assert.Equal(t, s.ID(), got.ID())
	}
}

func TestRegisterHTTPRejectsInvalidNames(t *testing.T) {
	r := New()
	s := sess("s1", 1, 0)
	for _, name := range []string{"", "ab", "a_b", "a.b", "-ab", "ab-", "a/b", "abc\x00", strings.Repeat("a", 64)} {
		err := r.RegisterHTTP(name, s)
		require.ErrorIs(t, err, reservations.ErrInvalidSubdomain, "name %q", name)
		_, ok := r.LookupHTTP(name)
		assert.False(t, ok, "name %q must not be registered", name)
	}
	// The rejected attempts left nothing behind: the session can still register.
	require.NoError(t, r.RegisterHTTP("fine", s))
}

func TestRegisterHTTPRejectsSystemReservedNames(t *testing.T) {
	r := New()
	s := sess("s1", 1, 0)
	for _, name := range []string{"www", "api", "app", "admin", "login", "tunnel", "status"} {
		err := r.RegisterHTTP(name, s)
		require.ErrorIs(t, err, reservations.ErrSystemReserved, "name %q", name)
		_, ok := r.LookupHTTP(name)
		assert.False(t, ok, "name %q must not be registered", name)
	}
}

// The registry stores names exactly as given, so it only takes names that
// are already in normal form: "MyApp" would be unreachable under "myapp".
func TestRegisterHTTPRejectsNamesNotInNormalForm(t *testing.T) {
	r := New()
	s := sess("s1", 1, 0)
	for _, name := range []string{"MyApp", " myapp", "myapp ", "MYAPP"} {
		err := r.RegisterHTTP(name, s)
		require.ErrorIs(t, err, reservations.ErrInvalidSubdomain, "name %q", name)
	}
	_, ok := r.LookupHTTP("myapp")
	assert.False(t, ok)
	assert.Empty(t, r.SnapshotAll())
}

// ---- Random names skip the reserved list ----

func scripted(names ...string) func() (string, error) {
	i := 0
	return func() (string, error) {
		if i >= len(names) {
			return "", errors.New("script exhausted")
		}
		n := names[i]
		i++
		return n, nil
	}
}

func TestGenerateRandomSubdomainSkipsSystemReservedNames(t *testing.T) {
	r := New()
	// "status", "signup", "static" and "tunnel" are six-letter names the
	// random generator can produce.
	r.candidate = scripted("status", "tunnel", "signup", "static", "qwerty", "unused")

	got, err := r.GenerateRandomSubdomain()
	require.NoError(t, err)
	assert.Equal(t, "qwerty", got)
}

func TestGenerateRandomSubdomainSkipsTakenNames(t *testing.T) {
	r := New()
	require.NoError(t, r.RegisterHTTP("taken1", sess("s1", 1, 0)))
	r.candidate = scripted("taken1", "free22")

	got, err := r.GenerateRandomSubdomain()
	require.NoError(t, err)
	assert.Equal(t, "free22", got)
}

func TestGenerateRandomSubdomainGivesUpAfterBoundedAttempts(t *testing.T) {
	r := New()
	calls := 0
	r.candidate = func() (string, error) { calls++; return "status", nil }

	_, err := r.GenerateRandomSubdomain()
	require.Error(t, err)
	assert.Equal(t, 100, calls)
}

// A failing random source ends the call with that error; it is not retried
// a hundred times and reported as "no free name".
func TestGenerateRandomSubdomainReturnsGeneratorError(t *testing.T) {
	r := New()
	broken := errors.New("entropy source failed")
	calls := 0
	r.candidate = func() (string, error) { calls++; return "", broken }

	got, err := r.GenerateRandomSubdomain()
	require.ErrorIs(t, err, broken)
	assert.Empty(t, got)
	assert.Equal(t, 1, calls)
}

func TestRandomCandidateShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := randomCandidate()
		require.NoError(t, err)
		require.Len(t, c, 6)
		for _, ch := range c {
			require.True(t, (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'), "unexpected character %q", ch)
		}
		seen[c] = true
	}
	assert.Greater(t, len(seen), 190, "candidates must differ")
}

// ---- Unregister{UDP,TCP,HTTP}: only the owner removes an entry ----

func TestUnregisterUDPOnlyForOwningSession(t *testing.T) {
	r := New()
	owner, other := sess("owner", 1, 0), sess("other", 2, 0)
	require.NoError(t, r.RegisterUDP(30001, owner))
	require.NoError(t, r.RegisterUDP(30002, other))

	assert.False(t, r.UnregisterUDP(30001, other), "a foreign session must not remove the entry")
	got, ok := r.LookupUDP(30001)
	require.True(t, ok)
	assert.Equal(t, "owner", got.ID())
	// The foreign session's own registration is untouched as well.
	got, ok = r.LookupUDP(30002)
	require.True(t, ok)
	assert.Equal(t, "other", got.ID())

	assert.True(t, r.UnregisterUDP(30001, owner))
	_, ok = r.LookupUDP(30001)
	assert.False(t, ok)
	assert.False(t, r.UnregisterUDP(30001, owner), "second call finds nothing")

	// The owner is free to take a port again; the other session still has one.
	require.NoError(t, r.RegisterUDP(30003, owner))
	assert.ErrorIs(t, r.RegisterUDP(30004, other), ErrSessionAlreadyRegisteredUDP)
}

func TestUnregisterTCPOnlyForOwningSession(t *testing.T) {
	r := New()
	owner, other := sess("owner", 1, 0), sess("other", 2, 0)
	require.NoError(t, r.RegisterTCP(20001, owner))
	require.NoError(t, r.RegisterTCP(20002, other))

	assert.False(t, r.UnregisterTCP(20001, other))
	got, ok := r.LookupTCP(20001)
	require.True(t, ok)
	assert.Equal(t, "owner", got.ID())

	assert.True(t, r.UnregisterTCP(20001, owner))
	_, ok = r.LookupTCP(20001)
	assert.False(t, ok)
	require.NoError(t, r.RegisterTCP(20003, owner))
	assert.ErrorIs(t, r.RegisterTCP(20004, other), ErrSessionAlreadyRegisteredTCP)
}

func TestUnregisterHTTPOnlyForOwningSession(t *testing.T) {
	r := New()
	owner, other := sess("owner", 1, 0), sess("other", 2, 0)
	require.NoError(t, r.RegisterHTTP("mine", owner))
	require.NoError(t, r.RegisterHTTP("theirs", other))

	assert.False(t, r.UnregisterHTTP("mine", other))
	got, ok := r.LookupHTTP("mine")
	require.True(t, ok)
	assert.Equal(t, "owner", got.ID())

	assert.True(t, r.UnregisterHTTP("mine", owner))
	_, ok = r.LookupHTTP("mine")
	assert.False(t, ok)
	require.NoError(t, r.RegisterHTTP("mine-again", owner))
	assert.ErrorIs(t, r.RegisterHTTP("more", other), ErrSessionAlreadyRegistered)
}

// Unregistering one tunnel keeps the session and its other tunnels.
func TestUnregisterOneTunnelKeepsTheSession(t *testing.T) {
	r := New()
	s := sess("s1", 1, 0)
	require.NoError(t, r.AddSession(s, SessionLimits{}))
	require.NoError(t, r.RegisterHTTP("keepme", s))
	require.NoError(t, r.RegisterUDP(30001, s))

	require.True(t, r.UnregisterUDP(30001, s))
	assert.Equal(t, []string{"http:s1:keepme:0"}, snapshotKeys(r))
	require.True(t, r.UnregisterHTTP("keepme", s))
	assert.Equal(t, []string{"session:s1::0"}, snapshotKeys(r), "the session itself stays tracked")
}

// A session that is torn down after its port went to a new owner must not
// take the new owner's entries with it.
func TestUnregisterLeavesEntriesOfOtherSessions(t *testing.T) {
	r := New()
	old, cur := sess("old", 1, 0), sess("cur", 2, 0)
	require.NoError(t, r.RegisterHTTP("name1", cur))
	require.NoError(t, r.RegisterTCP(20001, cur))
	require.NoError(t, r.RegisterUDP(30001, cur))

	r.Unregister(old)

	assert.Equal(t, []string{"http:cur:name1:0", "tcp:cur::20001", "udp:cur::30001"}, snapshotKeys(r))
}

// ---- Session tracking ----

func TestAddSessionMakesIdleSessionVisibleAndKillable(t *testing.T) {
	r := New()
	s := sess("idle1", 7, 3)
	require.NoError(t, r.AddSession(s, SessionLimits{}))

	snap := r.SnapshotAll()
	require.Len(t, snap, 1)
	assert.Equal(t, "idle1", snap[0].SessionID)
	assert.Equal(t, "session", snap[0].Type)
	assert.Equal(t, SnapshotTypeSession, snap[0].Type)
	assert.Empty(t, snap[0].Subdomain)
	assert.Zero(t, snap[0].Port)
	assert.Same(t, s, snap[0].Session.(*testSession))
	assert.Empty(t, r.Snapshot(), "Snapshot lists HTTP tunnels only")

	assert.True(t, r.KillSession("idle1"))
	assert.Equal(t, int32(1), s.closes.Load())
	assert.Empty(t, r.SnapshotAll())
	assert.False(t, r.KillSession("idle1"), "already gone")
	assert.Equal(t, int32(1), s.closes.Load())
}

func TestSnapshotAllListsEachSessionOncePerTunnel(t *testing.T) {
	r := New()
	idle, one, three := sess("idle", 1, 0), sess("one", 1, 0), sess("three", 2, 0)
	for _, s := range []*testSession{idle, one, three} {
		require.NoError(t, r.AddSession(s, SessionLimits{}))
	}
	require.NoError(t, r.RegisterHTTP("solo", one))
	require.NoError(t, r.RegisterHTTP("multi", three))
	require.NoError(t, r.RegisterTCP(20001, three))
	require.NoError(t, r.RegisterUDP(30001, three))

	assert.Equal(t, []string{
		"http:one:solo:0",
		"http:three:multi:0",
		"session:idle::0",
		"tcp:three::20001",
		"udp:three::30001",
	}, snapshotKeys(r))
}

func TestAddSessionRejectsDuplicateID(t *testing.T) {
	r := New()
	require.NoError(t, r.AddSession(sess("dup", 1, 0), SessionLimits{}))
	err := r.AddSession(sess("dup", 2, 0), SessionLimits{})
	require.ErrorIs(t, err, ErrSessionExists)
	assert.Len(t, r.SnapshotAll(), 1)
}

func TestUnregisterStopsTrackingTheSession(t *testing.T) {
	r := New()
	s := sess("s1", 1, 0)
	require.NoError(t, r.AddSession(s, SessionLimits{}))
	require.NoError(t, r.RegisterHTTP("gone", s))
	require.NoError(t, r.RegisterTCP(20001, s))
	require.NoError(t, r.RegisterUDP(30001, s))

	r.Unregister(s)

	assert.Empty(t, r.SnapshotAll())
	assert.False(t, r.KillSession("s1"))
	assert.False(t, s.closed(), "Unregister does not close")
	r.Unregister(s) // idempotent
	// The freed name and ports are available again.
	s2 := sess("s2", 2, 0)
	require.NoError(t, r.RegisterHTTP("gone", s2))
	require.NoError(t, r.RegisterTCP(20001, s2))
	require.NoError(t, r.RegisterUDP(30001, s2))
}

func TestKillSessionRemovesAllTunnelsOfTheSession(t *testing.T) {
	r := New()
	victim, bystander := sess("victim", 1, 0), sess("bystander", 1, 0)
	require.NoError(t, r.AddSession(victim, SessionLimits{}))
	require.NoError(t, r.AddSession(bystander, SessionLimits{}))
	require.NoError(t, r.RegisterHTTP("vhttp", victim))
	require.NoError(t, r.RegisterTCP(20001, victim))
	require.NoError(t, r.RegisterUDP(30001, victim))
	require.NoError(t, r.RegisterHTTP("bhttp", bystander))

	require.True(t, r.KillSession("victim"))

	assert.True(t, victim.closed())
	assert.False(t, bystander.closed())
	assert.Equal(t, []string{"http:bystander:bhttp:0"}, snapshotKeys(r))
}

// ---- Session limits ----

func TestAddSessionEnforcesPerUserLimit(t *testing.T) {
	r := New()
	lim := SessionLimits{PerUser: 2}
	a1, a2, a3 := sess("a1", 7, 0), sess("a2", 7, 0), sess("a3", 7, 0)
	require.NoError(t, r.AddSession(a1, lim))
	require.NoError(t, r.AddSession(a2, lim))
	require.ErrorIs(t, r.AddSession(a3, lim), ErrUserSessionLimit)
	assert.Len(t, r.SnapshotAll(), 2, "the rejected session is not tracked")

	// Another user is not affected.
	require.NoError(t, r.AddSession(sess("b1", 8, 0), lim))

	// A slot frees up when a session ends, whichever way it ends.
	r.Unregister(a1)
	require.NoError(t, r.AddSession(a3, lim))
	require.ErrorIs(t, r.AddSession(sess("a4", 7, 0), lim), ErrUserSessionLimit)
	require.True(t, r.KillSession("a2"))
	require.NoError(t, r.AddSession(sess("a5", 7, 0), lim))
}

// Static-token sessions have no user (ID 0); only the total limit applies.
func TestAddSessionPerUserLimitSkipsSessionsWithoutUser(t *testing.T) {
	r := New()
	lim := SessionLimits{PerUser: 1}
	for i := 0; i < 5; i++ {
		require.NoError(t, r.AddSession(sess(fmt.Sprintf("static%d", i), 0, 0), lim))
	}
}

func TestAddSessionEnforcesTotalLimit(t *testing.T) {
	r := New()
	lim := SessionLimits{Total: 3}
	require.NoError(t, r.AddSession(sess("s1", 1, 0), lim))
	require.NoError(t, r.AddSession(sess("s2", 2, 0), lim))
	require.NoError(t, r.AddSession(sess("s3", 0, 0), lim))
	require.ErrorIs(t, r.AddSession(sess("s4", 4, 0), lim), ErrSessionLimit)
	assert.Len(t, r.SnapshotAll(), 3)

	require.True(t, r.KillSession("s2"))
	require.NoError(t, r.AddSession(sess("s4", 4, 0), lim))
	require.ErrorIs(t, r.AddSession(sess("s5", 5, 0), lim), ErrSessionLimit)
}

// When both limits are hit the per-user limit is reported: it is the one the
// client can do something about.
func TestAddSessionReportsUserLimitBeforeTotalLimit(t *testing.T) {
	r := New()
	lim := SessionLimits{PerUser: 1, Total: 1}
	require.NoError(t, r.AddSession(sess("s1", 7, 0), lim))
	require.ErrorIs(t, r.AddSession(sess("s2", 7, 0), lim), ErrUserSessionLimit)
	require.ErrorIs(t, r.AddSession(sess("s3", 8, 0), lim), ErrSessionLimit)
}

// The zero value selects the defaults: 10 sessions per
// user and 350 in total.
func TestAddSessionZeroLimitsSelectTheDefaults(t *testing.T) {
	r := New()
	for i := 0; i < 10; i++ {
		require.NoError(t, r.AddSession(sess(fmt.Sprintf("u7-%d", i), 7, 0), SessionLimits{}), "session %d of user 7", i+1)
	}
	require.ErrorIs(t, r.AddSession(sess("u7-11th", 7, 0), SessionLimits{}), ErrUserSessionLimit)

	// Fill up to 350 with sessions of other users, one each.
	for i := 10; i < 350; i++ {
		require.NoError(t, r.AddSession(sess(fmt.Sprintf("s%d", i), int64(1000+i), 0), SessionLimits{}), "session %d in total", i+1)
	}
	require.ErrorIs(t, r.AddSession(sess("the-351st", 999999, 0), SessionLimits{}), ErrSessionLimit)
	assert.Len(t, r.SnapshotAll(), 350)
}

// A negative value disables a limit; the other limit keeps its meaning.
func TestAddSessionNegativeLimitsDisable(t *testing.T) {
	r := New()
	noUserLimit := SessionLimits{PerUser: -1}
	for i := 0; i < 50; i++ {
		require.NoError(t, r.AddSession(sess(fmt.Sprintf("u7-%d", i), 7, 0), noUserLimit))
	}
	// The per-user default still holds for a caller that does not disable it.
	require.ErrorIs(t, r.AddSession(sess("u7-default", 7, 0), SessionLimits{}), ErrUserSessionLimit)

	noTotalLimit := SessionLimits{PerUser: -1, Total: -1}
	for i := 50; i < 5001; i++ {
		require.NoError(t, r.AddSession(sess(fmt.Sprintf("s%d", i), int64(1000+i), 0), noTotalLimit))
	}
	assert.Len(t, r.SnapshotAll(), 5001)
	// The total default still holds for a caller that does not disable it.
	require.ErrorIs(t, r.AddSession(sess("over-default", 424242, 0), SessionLimits{}), ErrSessionLimit)
}

// Sessions that enter through a Register call count like any other.
func TestRegisterTracksSessionsThatWereNotAdded(t *testing.T) {
	r := New()
	s := sess("direct", 7, 0)
	require.NoError(t, r.RegisterTCP(20001, s))

	require.ErrorIs(t, r.AddSession(sess("next", 7, 0), SessionLimits{PerUser: 1}), ErrUserSessionLimit)
	require.ErrorIs(t, r.AddSession(sess("next", 8, 0), SessionLimits{Total: 1}), ErrSessionLimit)
	assert.Equal(t, 1, r.KillByUser(7))
	assert.True(t, s.closed())
}

func TestAddSessionTotalLimitHoldsUnderConcurrency(t *testing.T) {
	r := New()
	lim := SessionLimits{Total: 10}
	const attempts = 200
	var ok atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if err := r.AddSession(sess(fmt.Sprintf("s%d", i), int64(i+1), 0), lim); err == nil {
				ok.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	assert.Equal(t, int32(10), ok.Load())
	assert.Len(t, r.SnapshotAll(), 10)
}

// ---- KillByUser / KillByToken ----

func TestKillByUserClosesExactlyThatUsersSessions(t *testing.T) {
	r := New()
	a1, a2 := sess("a1", 1, 11), sess("a2", 1, 12)
	b1, static := sess("b1", 2, 21), sess("static", 0, 0)
	for _, s := range []*testSession{a1, a2, b1, static} {
		require.NoError(t, r.AddSession(s, SessionLimits{}))
	}
	require.NoError(t, r.RegisterHTTP("a-http", a1))
	require.NoError(t, r.RegisterTCP(20001, a1))
	require.NoError(t, r.RegisterUDP(30001, a1))
	require.NoError(t, r.RegisterHTTP("b-http", b1))
	// a2 has no tunnel at all.

	assert.Equal(t, 2, r.KillByUser(1))

	assert.Equal(t, int32(1), a1.closes.Load())
	assert.Equal(t, int32(1), a2.closes.Load())
	assert.False(t, b1.closed())
	assert.False(t, static.closed())
	assert.Equal(t, []string{"http:b1:b-http:0", "session:static::0"}, snapshotKeys(r))

	assert.Zero(t, r.KillByUser(1), "nothing left for that user")
	assert.Zero(t, r.KillByUser(99), "unknown user")
	assert.False(t, b1.closed())
}

// User ID 0 means "no user": it must never select the static-token sessions.
func TestKillByUserZeroIsANoOp(t *testing.T) {
	r := New()
	static := sess("static", 0, 0)
	require.NoError(t, r.AddSession(static, SessionLimits{}))

	assert.Zero(t, r.KillByUser(0))
	assert.Zero(t, r.KillByUser(-1))
	assert.False(t, static.closed())
	assert.Len(t, r.SnapshotAll(), 1)
}

func TestKillByTokenClosesExactlyThatTokensSessions(t *testing.T) {
	r := New()
	t11a, t11b := sess("t11a", 1, 11), sess("t11b", 1, 11)
	t12, other := sess("t12", 1, 12), sess("other", 2, 13)
	for _, s := range []*testSession{t11a, t11b, t12, other} {
		require.NoError(t, r.AddSession(s, SessionLimits{}))
	}
	require.NoError(t, r.RegisterHTTP("eleven", t11a))
	require.NoError(t, r.RegisterUDP(30001, t11b))
	require.NoError(t, r.RegisterHTTP("twelve", t12))

	assert.Equal(t, 2, r.KillByToken(11))

	assert.True(t, t11a.closed())
	assert.True(t, t11b.closed())
	assert.False(t, t12.closed(), "another token of the same user stays")
	assert.False(t, other.closed())
	assert.Equal(t, []string{"http:t12:twelve:0", "session:other::0"}, snapshotKeys(r))
	assert.Zero(t, r.KillByToken(11))
}

// Token ID 0 means "no token identity" (static-token mode). Killing "token 0"
// must not take down every such session.
func TestKillByTokenZeroIsANoOp(t *testing.T) {
	r := New()
	s1, s2 := sess("s1", 1, 0), sess("s2", 0, 0)
	require.NoError(t, r.AddSession(s1, SessionLimits{}))
	require.NoError(t, r.AddSession(s2, SessionLimits{}))

	assert.Zero(t, r.KillByToken(0))
	assert.Zero(t, r.KillByToken(-5))
	assert.False(t, s1.closed())
	assert.False(t, s2.closed())
}

// A session type without owner information cannot be matched by user or token.
func TestKillByUserIgnoresSessionsWithoutOwnerInformation(t *testing.T) {
	r := New()
	plain := &fakeCloser{fakeSession: fakeSession{id: "plain"}}
	require.NoError(t, r.AddSession(plain, SessionLimits{}))
	assert.Zero(t, r.KillByUser(1))
	assert.Zero(t, r.KillByToken(1))
	assert.False(t, plain.closed)
}

// ---- Evict… (a new reservation ends foreign sessions) ----

func TestEvictSubdomainSparesTheKeptUser(t *testing.T) {
	r := New()
	holder := sess("holder", 1, 0)
	require.NoError(t, r.AddSession(holder, SessionLimits{}))
	require.NoError(t, r.RegisterHTTP("wanted", holder))

	assert.Zero(t, r.EvictSubdomain("wanted", 1), "the owner of the reservation keeps the session")
	assert.False(t, holder.closed())
	_, ok := r.LookupHTTP("wanted")
	assert.True(t, ok)
}

func TestEvictSubdomainClosesForeignSession(t *testing.T) {
	r := New()
	holder, bystander := sess("holder", 1, 0), sess("bystander", 1, 0)
	require.NoError(t, r.AddSession(holder, SessionLimits{}))
	require.NoError(t, r.AddSession(bystander, SessionLimits{}))
	require.NoError(t, r.RegisterHTTP("wanted", holder))
	require.NoError(t, r.RegisterTCP(20001, holder))
	require.NoError(t, r.RegisterHTTP("unrelated", bystander))

	assert.Equal(t, 1, r.EvictSubdomain("wanted", 2))

	assert.Equal(t, int32(1), holder.closes.Load())
	assert.False(t, bystander.closed(), "other sessions of the same user are not the target")
	assert.Equal(t, []string{"http:bystander:unrelated:0"}, snapshotKeys(r),
		"the evicted session is gone with all its tunnels")
	assert.Zero(t, r.EvictSubdomain("wanted", 2), "nothing left to evict")
	assert.Zero(t, r.EvictSubdomain("nobody-has-this", 2))
}

func TestEvictSubdomainNormalisesTheName(t *testing.T) {
	r := New()
	holder := sess("holder", 1, 0)
	require.NoError(t, r.RegisterHTTP("wanted", holder))
	assert.Equal(t, 1, r.EvictSubdomain("  Wanted ", 2))
	assert.True(t, holder.closed())
}

// A name that is not a valid subdomain names no tunnel. In particular the
// Kelvin sign is not a "k": "\u212Aey" must not evict the holder of "key".
func TestEvictSubdomainIgnoresNamesThatAreNotValid(t *testing.T) {
	r := New()
	holder := sess("holder", 1, 0)
	require.NoError(t, r.RegisterHTTP("key", holder))

	for _, name := range []string{"\u212Aey", "ke_y", "k.ey", "", "   ", "admin"} {
		assert.Zero(t, r.EvictSubdomain(name, 2), "name %q", name)
	}
	assert.False(t, holder.closed())
	got, ok := r.LookupHTTP("key")
	require.True(t, ok)
	assert.Equal(t, "holder", got.ID())

	// The valid spelling still evicts.
	assert.Equal(t, 1, r.EvictSubdomain("KEY", 2))
	assert.True(t, holder.closed())
}

// A session without a user (static token) is foreign to every real user.
func TestEvictTreatsUserlessSessionAsForeign(t *testing.T) {
	r := New()
	static := sess("static", 0, 0)
	require.NoError(t, r.RegisterHTTP("wanted", static))
	assert.Equal(t, 1, r.EvictSubdomain("wanted", 5))
	assert.True(t, static.closed())
}

func TestEvictTCPPortSparesKeptUserAndOtherProtocols(t *testing.T) {
	r := New()
	tcpHolder, udpHolder := sess("tcp-holder", 1, 0), sess("udp-holder", 3, 0)
	require.NoError(t, r.RegisterTCP(5000, tcpHolder))
	require.NoError(t, r.RegisterUDP(5000, udpHolder)) // same number, other protocol

	assert.Zero(t, r.EvictTCPPort(5000, 1))
	assert.False(t, tcpHolder.closed())
	assert.Zero(t, r.EvictTCPPort(5001, 2), "nobody holds 5001")

	assert.Equal(t, 1, r.EvictTCPPort(5000, 2))
	assert.True(t, tcpHolder.closed())
	assert.False(t, udpHolder.closed(), "the UDP tunnel on the same port number is unrelated")
	assert.Equal(t, []string{"udp:udp-holder::5000"}, snapshotKeys(r))
}

func TestEvictUDPPortSparesKeptUserAndOtherProtocols(t *testing.T) {
	r := New()
	tcpHolder, udpHolder := sess("tcp-holder", 1, 0), sess("udp-holder", 3, 0)
	require.NoError(t, r.RegisterTCP(5000, tcpHolder))
	require.NoError(t, r.RegisterUDP(5000, udpHolder))

	assert.Zero(t, r.EvictUDPPort(5000, 3))
	assert.False(t, udpHolder.closed())
	assert.Zero(t, r.EvictUDPPort(5001, 2))

	assert.Equal(t, 1, r.EvictUDPPort(5000, 2))
	assert.True(t, udpHolder.closed())
	assert.False(t, tcpHolder.closed(), "the TCP tunnel on the same port number is unrelated")
	assert.Equal(t, []string{"tcp:tcp-holder::5000"}, snapshotKeys(r))
}

// Close runs outside the registry lock: a session whose Close calls back into
// the registry must not deadlock.
type reentrantSession struct {
	testSession
	reg *Registry
}

func (s *reentrantSession) Close() error {
	s.reg.Unregister(s)
	_ = s.reg.SnapshotAll()
	return s.testSession.Close()
}

func TestKillDoesNotHoldTheLockWhileClosing(t *testing.T) {
	r := New()
	s := &reentrantSession{testSession: testSession{id: "re", userID: 1, tokenID: 9}, reg: r}
	require.NoError(t, r.AddSession(s, SessionLimits{}))
	require.NoError(t, r.RegisterHTTP("reentrant", s))

	done := make(chan int, 1)
	go func() { done <- r.KillByUser(1) }()
	select {
	case n := <-done:
		assert.Equal(t, 1, n)
	case <-time.After(15 * time.Second):
		t.Fatal("KillByUser deadlocked on a session that re-enters the registry")
	}
	assert.Equal(t, int32(1), s.closes.Load())
}

// The service API closes whoever holds the port, also a session of the
// account that becomes the holder and one without a user.
func TestCloseTCPPortHolderClosesAnyUser(t *testing.T) {
	r := New()
	holder, idle := sess("holder", 7, 0), sess("idle", 7, 0)
	static := sess("static", 0, 0)
	require.NoError(t, r.RegisterTCP(5000, holder))
	require.NoError(t, r.RegisterTCP(5002, static))
	require.NoError(t, r.AddSession(idle, SessionLimits{}))

	assert.Zero(t, r.CloseTCPPortHolder(5001), "nobody holds 5001")
	assert.Equal(t, 1, r.CloseTCPPortHolder(5000))
	assert.True(t, holder.closed())
	assert.False(t, idle.closed(), "only the holder of the port is closed")
	_, ok := r.LookupTCP(5000)
	assert.False(t, ok)

	assert.Equal(t, 1, r.CloseTCPPortHolder(5002))
	assert.True(t, static.closed())
}
