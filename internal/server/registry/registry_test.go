package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSession struct{ id string }

func (f *fakeSession) ID() string { return f.id }

func TestRegisterAndLookup(t *testing.T) {
	r := New()
	s := &fakeSession{id: "s1"}

	err := r.RegisterHTTP("abc", s)
	require.NoError(t, err)

	got, ok := r.LookupHTTP("abc")
	require.True(t, ok)
	assert.Equal(t, "s1", got.(*fakeSession).ID())
}

func TestRegisterDuplicateSubdomain(t *testing.T) {
	r := New()
	s1 := &fakeSession{id: "s1"}
	s2 := &fakeSession{id: "s2"}

	require.NoError(t, r.RegisterHTTP("abc", s1))
	err := r.RegisterHTTP("abc", s2)
	assert.ErrorIs(t, err, ErrSubdomainTaken)
}

func TestRegisterRejectsSecondSubdomainForSameSession(t *testing.T) {
	r := New()
	s := &fakeSession{id: "s1"}

	require.NoError(t, r.RegisterHTTP("abc", s))
	err := r.RegisterHTTP("def", s)
	assert.ErrorIs(t, err, ErrSessionAlreadyRegistered)

	// The first registration is still intact.
	_, ok := r.LookupHTTP("abc")
	assert.True(t, ok)
	_, ok = r.LookupHTTP("def")
	assert.False(t, ok)
}

func TestUnregister(t *testing.T) {
	r := New()
	s := &fakeSession{id: "s1"}

	require.NoError(t, r.RegisterHTTP("abc", s))
	r.Unregister(s)

	_, ok := r.LookupHTTP("abc")
	assert.False(t, ok)
}

func TestSnapshotReturnsAllSessions(t *testing.T) {
	r := New()
	s1 := &fakeSession{id: "s1"}
	s2 := &fakeSession{id: "s2"}

	require.NoError(t, r.RegisterHTTP("one", s1))
	require.NoError(t, r.RegisterHTTP("two", s2))

	snap := r.Snapshot()
	require.Len(t, snap, 2)

	got := map[string]string{}
	for _, e := range snap {
		got[e.Subdomain] = e.Session.ID()
	}
	assert.Equal(t, "s1", got["one"])
	assert.Equal(t, "s2", got["two"])

	// Confirm it's a detached copy: mutating the snapshot doesn't affect the registry.
	snap[0].Subdomain = "mutated"
	_, ok := r.LookupHTTP("one")
	assert.True(t, ok)
}

func TestRegisterTCPAndLookup(t *testing.T) {
	r := New()
	s := &fakeSession{id: "s1"}
	require.NoError(t, r.RegisterTCP(12345, s))
	got, ok := r.LookupTCP(12345)
	require.True(t, ok)
	assert.Equal(t, "s1", got.(*fakeSession).ID())
}

func TestRegisterTCPDuplicatePort(t *testing.T) {
	r := New()
	s1 := &fakeSession{id: "s1"}
	s2 := &fakeSession{id: "s2"}
	require.NoError(t, r.RegisterTCP(12345, s1))
	err := r.RegisterTCP(12345, s2)
	assert.ErrorIs(t, err, ErrPortTaken)
}

func TestRegisterTCPSecondPortSameSession(t *testing.T) {
	r := New()
	s := &fakeSession{id: "s1"}
	require.NoError(t, r.RegisterTCP(12345, s))
	err := r.RegisterTCP(12346, s)
	assert.ErrorIs(t, err, ErrSessionAlreadyRegisteredTCP)
}

func TestRegisterHTTPAndTCPSameSession(t *testing.T) {
	r := New()
	s := &fakeSession{id: "s1"}
	require.NoError(t, r.RegisterHTTP("abc", s))
	require.NoError(t, r.RegisterTCP(12345, s))
	_, ok := r.LookupHTTP("abc")
	assert.True(t, ok)
	_, ok = r.LookupTCP(12345)
	assert.True(t, ok)
}

func TestUnregisterClearsBothMaps(t *testing.T) {
	r := New()
	s := &fakeSession{id: "s1"}
	require.NoError(t, r.RegisterHTTP("abc", s))
	require.NoError(t, r.RegisterTCP(12345, s))
	r.Unregister(s)
	_, ok := r.LookupHTTP("abc")
	assert.False(t, ok)
	_, ok = r.LookupTCP(12345)
	assert.False(t, ok)
}

func TestGenerateRandomSubdomainNoCollision(t *testing.T) {
	r := New()
	s1 := &fakeSession{id: "s1"}

	sd, err := r.GenerateRandomSubdomain()
	require.NoError(t, err)
	assert.Len(t, sd, 6)

	require.NoError(t, r.RegisterHTTP(sd, s1))

	for i := 0; i < 100; i++ {
		next, err := r.GenerateRandomSubdomain()
		require.NoError(t, err)
		assert.NotEqual(t, sd, next)
	}
}

func TestRegisterUDPAndUnregister(t *testing.T) {
	r := New()
	s := &fakeSession{id: "s1"}

	require.NoError(t, r.RegisterUDP(30001, s))

	got, ok := r.LookupUDP(30001)
	require.True(t, ok)
	assert.Equal(t, "s1", got.(*fakeSession).ID())

	require.True(t, r.UnregisterUDP(30001, s))

	got, ok = r.LookupUDP(30001)
	assert.False(t, ok)
	assert.Nil(t, got)
}

func TestSnapshotAllMergesAllTypes(t *testing.T) {
	r := New()
	http1 := &fakeSession{id: "http1"}
	tcp1 := &fakeSession{id: "tcp1"}
	udp1 := &fakeSession{id: "udp1"}

	require.NoError(t, r.RegisterHTTP("webapp", http1))
	require.NoError(t, r.RegisterTCP(9000, tcp1))
	require.NoError(t, r.RegisterUDP(9001, udp1))

	snap := r.SnapshotAll()
	require.Len(t, snap, 3)

	byID := map[string]SnapshotEntry{}
	for _, e := range snap {
		byID[e.SessionID] = e
	}

	httpE := byID["http1"]
	assert.Equal(t, "http", httpE.Type)
	assert.Equal(t, "webapp", httpE.Subdomain)
	assert.Equal(t, 0, httpE.Port)

	tcpE := byID["tcp1"]
	assert.Equal(t, "tcp", tcpE.Type)
	assert.Equal(t, 9000, tcpE.Port)
	assert.Equal(t, "", tcpE.Subdomain)

	udpE := byID["udp1"]
	assert.Equal(t, "udp", udpE.Type)
	assert.Equal(t, 9001, udpE.Port)
}

func TestSnapshotEntryCarriesSessionID(t *testing.T) {
	r := New()
	s := &fakeSession{id: "sess-xyz"}
	require.NoError(t, r.RegisterHTTP("sub", s))

	snap := r.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, "sess-xyz", snap[0].SessionID)
}

// fakeCloser implements Session + Closer so KillSession tests can verify Close is called.
type fakeCloser struct {
	fakeSession
	closed bool
}

func (f *fakeCloser) Close() error {
	f.closed = true
	return nil
}

func TestKillSessionHTTP(t *testing.T) {
	r := New()
	s := &fakeCloser{fakeSession: fakeSession{id: "kill1"}}

	require.NoError(t, r.RegisterHTTP("victim", s))
	require.True(t, r.KillSession("kill1"))
	assert.True(t, s.closed)

	_, ok := r.LookupHTTP("victim")
	assert.False(t, ok)
}

func TestKillSessionTCP(t *testing.T) {
	r := New()
	s := &fakeCloser{fakeSession: fakeSession{id: "kill2"}}

	require.NoError(t, r.RegisterTCP(7000, s))
	require.True(t, r.KillSession("kill2"))
	assert.True(t, s.closed)

	_, ok := r.LookupTCP(7000)
	assert.False(t, ok)
}

func TestKillSessionNotFound(t *testing.T) {
	r := New()
	assert.False(t, r.KillSession("nonexistent"))
}
