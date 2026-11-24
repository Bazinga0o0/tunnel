package acceptor

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeudp"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

// streamClient is the tunnel client's end of a session: it accepts every
// stream the server opens and keeps it open until the test closes it.
type streamClient struct {
	sess     protocol.Session
	accepted chan protocol.Stream
}

// userSession builds a TunnelSession of userID over a real yamux session,
// with the per-session limit maxStreams and the per-user limiter u.
func userSession(t *testing.T, id string, userID int64, maxStreams int, u *userStreams) (*TunnelSession, *streamClient) {
	t.Helper()
	ln, err := net.Listen("tcp", testports.Loopback+":0")
	require.NoError(t, err)
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	serverConn := <-ch
	require.NotNil(t, serverConn)

	server, err := protocol.NewServerSession(serverConn)
	require.NoError(t, err)
	client, err := protocol.NewClientSession(clientConn)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	// The control stream, as in a real session.
	_, err = client.OpenStream()
	require.NoError(t, err)
	_, err = server.AcceptStream()
	require.NoError(t, err)

	sc := &streamClient{sess: client, accepted: make(chan protocol.Stream, 1024)}
	go func() {
		for {
			st, err := client.AcceptStream()
			if err != nil {
				return
			}
			sc.accepted <- st
		}
	}()
	ts := newTunnelSession(id, userID, 0, server, maxStreams)
	if userID > 0 {
		ts.user = u
	}
	return ts, sc
}

// next returns the next stream the server opened towards the client.
func (c *streamClient) next(t *testing.T) protocol.Stream {
	t.Helper()
	select {
	case st := <-c.accepted:
		return st
	case <-time.After(waitFor):
		t.Fatal("the server opened no stream")
		return nil
	}
}

func openN(t *testing.T, ts *TunnelSession, n int) []protocol.Stream {
	t.Helper()
	out := make([]protocol.Stream, 0, n)
	for i := 0; i < n; i++ {
		s, err := ts.OpenStream()
		require.NoError(t, err, "stream %d of session %s", i+1, ts.ID())
		out = append(out, s)
	}
	return out
}

func requireHeld(t *testing.T, u *userStreams, userID int64, want int) {
	t.Helper()
	require.Eventually(t, func() bool { return u.held(userID) == want }, waitFor, 10*time.Millisecond,
		"user %d holds %d streams, want %d", userID, u.held(userID), want)
}

func TestStreamsOfAllSessionsOfAUserShareOneLimit(t *testing.T) {
	u := newUserStreams(3)
	a1, c1 := userSession(t, "a1", 1, 0, u)
	a2, _ := userSession(t, "a2", 1, 0, u)
	b, _ := userSession(t, "b", 2, 0, u)

	first, err := a1.OpenStream()
	require.NoError(t, err)
	firstPeer := c1.next(t)
	openN(t, a1, 1)
	openN(t, a2, 1)
	for _, ts := range []*TunnelSession{a1, a2} {
		_, err := ts.OpenStream()
		require.ErrorIs(t, err, ErrTooManyStreams, "session %s: the user's sessions hold 3 streams together", ts.ID())
		require.ErrorIs(t, err, ErrTooManyUserStreams)
	}
	assert.Equal(t, 3, u.held(1))

	// Another user is not affected.
	openN(t, b, 3)
	_, err = b.OpenStream()
	require.ErrorIs(t, err, ErrTooManyUserStreams)

	// A stream closed on both sides frees a slot, also for the other
	// session.
	require.NoError(t, first.Close())
	require.NoError(t, firstPeer.Close())
	require.Eventually(t, func() bool { return a1.liveDataStreams() == 1 }, waitFor, 10*time.Millisecond)
	openN(t, a2, 1)
	_, err = a1.OpenStream()
	require.ErrorIs(t, err, ErrTooManyUserStreams)
}

// A stream the server has closed still holds its buffers while the client
// keeps its side open. The user's limit counts it, like the session's does.
func TestUserStreamLimitCountsStreamsTheClientKeepsOpen(t *testing.T) {
	u := newUserStreams(2)
	a1, c1 := userSession(t, "a1", 1, 0, u)
	a2, _ := userSession(t, "a2", 1, 0, u)

	for _, s := range openN(t, a1, 2) {
		require.NoError(t, s.Close())
	}
	peer := c1.next(t)
	c1.next(t)
	assert.Zero(t, u.held(1), "the server holds no stream any more")
	_, err := a2.OpenStream()
	require.ErrorIs(t, err, ErrTooManyUserStreams, "both streams are still open on the client's side")

	require.NoError(t, peer.Close())
	require.Eventually(t, func() bool {
		s, err := a2.OpenStream()
		if err == nil {
			defer s.Close()
		}
		return err == nil
	}, waitFor, 10*time.Millisecond)
}

func TestUserStreamLimitDefaultAndDisabled(t *testing.T) {
	assert.Equal(t, 256, New(staticOpts()).lim.maxStreamsPerUser)
	assert.NotNil(t, New(staticOpts()).userStreams)

	opts := staticOpts()
	opts.MaxStreamsPerUser = -1
	acc := New(opts)
	assert.Zero(t, acc.lim.maxStreamsPerUser)
	assert.Nil(t, acc.userStreams, "negative disables the limit")

	opts.MaxStreamsPerUser = 7
	assert.Equal(t, 7, New(opts).lim.maxStreamsPerUser)
}

// tcpEdge is a real TCP edge on a free loopback port range.
func tcpEdge(t *testing.T, ports int) *edgetcp.Manager {
	t.Helper()
	low, high := testports.FreeTCPRange(t, ports)
	return edgetcp.NewWithOptions(edgetcp.Options{BindHost: testports.Loopback, Pool: edgetcp.NewPool(low, high)})
}

func visit(t *testing.T, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(testports.Loopback, strconv.Itoa(port)), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// The count of a user's streams goes back to zero on every way a stream or a
// session ends.
func TestUserStreamCountReturnsToZero(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	t.Run("visitor closes", func(t *testing.T) {
		u := newUserStreams(8)
		ts, c := userSession(t, "s", 1, 0, u)
		edge := tcpEdge(t, 1)
		port, err := edge.Open(ctx, 0, ts)
		require.NoError(t, err)
		defer edge.Close(port)
		v := visit(t, port)
		c.next(t)
		requireHeld(t, u, 1, 1)
		require.NoError(t, v.Close())
		requireHeld(t, u, 1, 0)
	})

	t.Run("client closes", func(t *testing.T) {
		u := newUserStreams(8)
		ts, c := userSession(t, "s", 1, 0, u)
		low, high := testports.FreeUDPRange(t, 1)
		edge := edgeudp.New(edgeudp.Options{BindHost: testports.Loopback, Pool: edgeudp.NewPool(low, high)})
		port, err := edge.Open(ctx, 0, ts)
		require.NoError(t, err)
		defer edge.Close(port)
		v, err := net.Dial("udp", net.JoinHostPort(testports.Loopback, strconv.Itoa(port)))
		require.NoError(t, err)
		defer v.Close()
		_, err = v.Write([]byte("hello"))
		require.NoError(t, err)
		st := c.next(t)
		requireHeld(t, u, 1, 1)
		require.NoError(t, st.Close())
		requireHeld(t, u, 1, 0)
	})

	t.Run("kill", func(t *testing.T) {
		u := newUserStreams(8)
		ts, c := userSession(t, "s", 1, 0, u)
		reg := registry.New()
		require.NoError(t, reg.AddSession(ts, registry.SessionLimits{}))
		edge := tcpEdge(t, 1)
		port, err := edge.Open(ctx, 0, ts)
		require.NoError(t, err)
		defer edge.Close(port)
		visit(t, port)
		visit(t, port)
		c.next(t)
		c.next(t)
		requireHeld(t, u, 1, 2)
		require.Equal(t, 1, reg.KillByUser(1))
		requireHeld(t, u, 1, 0)
	})

	t.Run("eviction", func(t *testing.T) {
		u := newUserStreams(8)
		ts, c := userSession(t, "s", 1, 0, u)
		reg := registry.New()
		edge := tcpEdge(t, 1)
		port, err := edge.Open(ctx, 0, ts)
		require.NoError(t, err)
		defer edge.Close(port)
		require.NoError(t, reg.RegisterTCP(port, ts))
		visit(t, port)
		c.next(t)
		requireHeld(t, u, 1, 1)
		require.Equal(t, 1, reg.EvictTCPPort(port, 2))
		requireHeld(t, u, 1, 0)
	})

	t.Run("refused open", func(t *testing.T) {
		u := newUserStreams(1)
		ts, c := userSession(t, "s", 1, 0, u)
		edge := tcpEdge(t, 1)
		port, err := edge.Open(ctx, 0, ts)
		require.NoError(t, err)
		defer edge.Close(port)
		first := visit(t, port)
		c.next(t)
		requireHeld(t, u, 1, 1)
		// Over the limit the edge closes the visitor without a stream, and
		// the refused attempt holds nothing.
		requireConnClosed(t, visit(t, port), waitFor)
		assert.Equal(t, 1, u.held(1))
		require.NoError(t, first.Close())
		requireHeld(t, u, 1, 0)

		// A stream the yamux session refuses gives its slot back as well.
		under := &pipeSession{fail: errors.New("session shutdown")}
		failing := newTunnelSession("f", 3, 0, under, 0)
		failing.user = u
		_, err = failing.OpenStream()
		require.EqualError(t, err, "session shutdown")
		assert.Zero(t, u.held(3))
		under.mu.Lock()
		under.fail = nil
		under.mu.Unlock()
		s, err := failing.OpenStream()
		require.NoError(t, err, "the failed attempt kept the user's only slot")
		require.NoError(t, s.Close())
		assert.Zero(t, u.held(3))
	})

	t.Run("session closes with streams open", func(t *testing.T) {
		u := newUserStreams(8)
		ts, _ := userSession(t, "s", 1, 0, u)
		openN(t, ts, 3) // the edges have not closed them (yet)
		require.Equal(t, 3, u.held(1))
		require.NoError(t, ts.Close())
		assert.Zero(t, u.held(1))
		assert.Empty(t, u.users, "nothing is kept for a user without sessions")
		_, err := ts.OpenStream()
		require.Error(t, err, "a closed session opens no stream")
		assert.Zero(t, u.held(1))
	})
}

// ---- through the tunnel listener ----

// collect accepts the streams of a logged-in test client and keeps them open.
func (c *client) collect() chan protocol.Stream {
	out := make(chan protocol.Stream, 64)
	go func() {
		for {
			st, err := c.sess.AcceptStream()
			if err != nil {
				return
			}
			out <- st
		}
	}()
	return out
}

func requireStream(t *testing.T, ch chan protocol.Stream) protocol.Stream {
	t.Helper()
	select {
	case st := <-ch:
		return st
	case <-time.After(waitFor):
		t.Fatal("no stream reached the tunnel client")
		return nil
	}
}

// Two sessions of one user share tunnel.max_streams_per_user; another user
// is not affected; the count is back at zero when the sessions end.
func TestUserStreamLimitThroughTheTunnelListener(t *testing.T) {
	fx := newDBFixture(t)
	alice, aliceToken := fx.user(t, "alice@example.com")
	bob, bobToken := fx.user(t, "bob@example.com")
	opts := fx.dbOpts()
	opts.TCPEdge = tcpEdge(t, 3)
	opts.MaxStreamsPerUser = 2
	addr, acc := serve(t, opts, nil)

	a1, _ := login(t, addr, aliceToken)
	a2, _ := login(t, addr, aliceToken)
	b, _ := login(t, addr, bobToken)
	ports := map[*client]int{}
	streams := map[*client]chan protocol.Stream{}
	for _, c := range []*client{a1, a2, b} {
		ack := c.registerTCP(0)
		require.Empty(t, ack.Error)
		ports[c] = ack.Port
		streams[c] = c.collect()
	}

	v1 := visit(t, ports[a1])
	s1 := requireStream(t, streams[a1])
	visit(t, ports[a2])
	requireStream(t, streams[a2])
	require.Equal(t, 2, acc.userStreams.held(alice))

	// The third visitor of alice's tunnels is refused, whichever tunnel.
	requireConnClosed(t, visit(t, ports[a1]), waitFor)
	requireConnClosed(t, visit(t, ports[a2]), waitFor)
	// Bob's tunnel is not affected.
	visit(t, ports[b])
	requireStream(t, streams[b])
	visit(t, ports[b])
	requireStream(t, streams[b])
	require.Equal(t, 2, acc.userStreams.held(bob))

	// A visitor leaves and the client closes its end of the stream, as
	// the tunnel client does at the end of the stream: there is room for
	// one again.
	require.NoError(t, v1.Close())
	require.Eventually(t, func() bool { return acc.userStreams.held(alice) == 1 }, waitFor, 10*time.Millisecond)
	require.NoError(t, s1.Close())
	require.Eventually(t, func() bool {
		v := visit(t, ports[a1])
		select {
		case <-streams[a1]:
			return true
		case <-time.After(200 * time.Millisecond):
			_ = v.Close()
			return false
		}
	}, waitFor, 10*time.Millisecond)

	// The sessions end: nothing is left counted.
	for _, c := range []*client{a1, a2, b} {
		require.NoError(t, c.sess.Close())
	}
	require.Eventually(t, func() bool {
		return acc.userStreams.held(alice) == 0 && acc.userStreams.held(bob) == 0 && acc.userStreams.users0()
	}, waitFor, 10*time.Millisecond)
}

// Static-token sessions have no user: the per-user limit does not apply to
// them (tunnel.max_streams_per_session still does).
func TestUserStreamLimitDoesNotApplyInStaticMode(t *testing.T) {
	reg := registry.New()
	opts := staticOpts()
	opts.Registry = reg
	opts.MaxStreamsPerUser = 1
	addr, _ := serve(t, opts, nil)
	login(t, addr, staticToken)
	var ts *TunnelSession
	require.Eventually(t, func() bool {
		for _, e := range reg.SnapshotAll() {
			ts, _ = e.Session.(*TunnelSession)
		}
		return ts != nil
	}, waitFor, 10*time.Millisecond)
	assert.Nil(t, ts.user)
}

// shrinkCountingSession wraps a session so that the streams it accepts (the
// control stream) count the calls of Shrink.
type shrinkCountingSession struct {
	protocol.Session
	shrinks *atomic.Int32
}

type shrinkCountingStream struct {
	protocol.Stream
	shrinks *atomic.Int32
}

func (s shrinkCountingStream) Shrink() { s.shrinks.Add(1) }

func (s shrinkCountingStream) SetReadDeadline(t time.Time) error {
	return s.Stream.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(t)
}

func (s shrinkCountingSession) AcceptStream() (protocol.Stream, error) {
	st, err := s.Session.AcceptStream()
	if err != nil {
		return nil, err
	}
	return shrinkCountingStream{Stream: st, shrinks: s.shrinks}, nil
}

// A burst of control frames makes the control stream's receive buffer grow
// while the session is busy with one of them; yamux keeps it at that size
// for the life of the session unless the stream is told to give an empty
// buffer back, which the acceptor does after each frame.
func TestControlStreamGivesBackItsEmptyBuffer(t *testing.T) {
	shrinks := &atomic.Int32{}
	opts := staticOpts()
	addr, _ := serve(t, opts, func(a *Acceptor) {
		inner := a.newSession
		a.newSession = func(conn io.ReadWriteCloser, o protocol.ServerOptions) (protocol.Session, error) {
			s, err := inner(conn, o)
			if err != nil {
				return nil, err
			}
			return shrinkCountingSession{Session: s, shrinks: shrinks}, nil
		}
	})
	c, _ := login(t, addr, staticToken)
	before := shrinks.Load()
	for i := 0; i < 3; i++ {
		c.requireOpen()
	}
	assert.GreaterOrEqual(t, shrinks.Load()-before, int32(3), "one Shrink per control frame")
}

// users0 reports whether the limiter keeps no entry at all.
func (u *userStreams) users0() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.users) == 0
}
