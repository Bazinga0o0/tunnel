package acceptor

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// pipeSession is a protocol.Session whose streams are in-process pipes. It
// does not count live streams, so it shows the semaphore on its own.
type pipeSession struct {
	mu     sync.Mutex
	opened int
	peers  []protocol.Stream
	fail   error
}

func (p *pipeSession) OpenStream() (protocol.Stream, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.opened++
	if p.fail != nil {
		return nil, p.fail
	}
	local, peer := protocol.PipeStream()
	p.peers = append(p.peers, peer)
	return local, nil
}

func (p *pipeSession) AcceptStream() (protocol.Stream, error) { return nil, io.EOF }
func (p *pipeSession) Close() error                           { return nil }

func (p *pipeSession) openCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.opened
}

func TestOpenStreamFailsAtOnceWhenTheLimitIsReached(t *testing.T) {
	under := &pipeSession{}
	ts := newTunnelSession("s1", 1, 0, under, 2)

	s1, err := ts.OpenStream()
	require.NoError(t, err)
	_, err = ts.OpenStream()
	require.NoError(t, err)

	// The refused call returns although no slot becomes free in the meantime.
	type result struct {
		stream protocol.Stream
		err    error
	}
	returned := make(chan result, 1)
	go func() {
		s, err := ts.OpenStream()
		returned <- result{s, err}
	}()
	select {
	case r := <-returned:
		require.ErrorIs(t, r.err, ErrTooManyStreams)
		assert.Nil(t, r.stream)
	case <-time.After(waitFor):
		t.Fatal("OpenStream waits for a free slot instead of failing")
	}
	assert.Equal(t, 2, under.openCalls(), "a refused call must not reach the session")

	// Closing a stream frees its slot ...
	require.NoError(t, s1.Close())
	s4, err := ts.OpenStream()
	require.NoError(t, err)
	// ... exactly once, however often Close is called.
	require.NoError(t, s1.Close())
	_ = s1.Close()
	_, err = ts.OpenStream()
	require.ErrorIs(t, err, ErrTooManyStreams)

	require.NoError(t, s4.Close())
	_, err = ts.OpenStream()
	require.NoError(t, err)
}

func TestOpenStreamDefaultLimitIs512(t *testing.T) {
	ts := newTunnelSession("s1", 1, 0, &pipeSession{}, New(staticOpts()).lim.maxStreams)
	var streams []protocol.Stream
	for i := 0; i < 512; i++ {
		s, err := ts.OpenStream()
		require.NoError(t, err, "stream %d", i+1)
		streams = append(streams, s)
	}
	_, err := ts.OpenStream()
	require.ErrorIs(t, err, ErrTooManyStreams, "the 513th stream")
	for _, s := range streams {
		_ = s.Close()
	}
}

func TestOpenStreamReleasesTheSlotWhenOpeningFails(t *testing.T) {
	under := &pipeSession{fail: errors.New("session shutdown")}
	ts := newTunnelSession("s1", 1, 0, under, 1)

	_, err := ts.OpenStream()
	require.EqualError(t, err, "session shutdown")

	under.mu.Lock()
	under.fail = nil
	under.mu.Unlock()
	_, err = ts.OpenStream()
	require.NoError(t, err, "the failed attempt must not keep the only slot")
}

func TestOpenStreamWithoutLimit(t *testing.T) {
	ts := newTunnelSession("s1", 1, 0, &pipeSession{}, 0)
	for i := 0; i < 600; i++ {
		s, err := ts.OpenStream()
		require.NoError(t, err)
		defer s.Close()
	}
}

// The edges set deadlines on streams; the wrapper that releases the slot must
// not hide those methods, and data must pass through it unchanged.
func TestLimitedStreamKeepsConnMethodsAndData(t *testing.T) {
	under := &pipeSession{}
	ts := newTunnelSession("s1", 1, 0, under, 4)
	s, err := ts.OpenStream()
	require.NoError(t, err)
	defer s.Close()

	conn, ok := s.(net.Conn)
	require.True(t, ok, "a stream that is a net.Conn stays one")
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = conn.Read(make([]byte, 1))
	require.True(t, isTimeout(err), "the deadline must reach the underlying stream: %v", err)
	require.NoError(t, conn.SetReadDeadline(time.Time{}))

	peer := under.peers[0]
	go func() { _, _ = peer.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	_, err = io.ReadFull(s, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))
}

// shrinkSession hands out pipe streams that count the calls of Shrink.
type shrinkSession struct {
	pipeSession
	shrinks atomic.Int32
}

type shrinkConn struct {
	net.Conn
	shrinks *atomic.Int32
}

func (s shrinkConn) Shrink() { s.shrinks.Add(1) }

func (s *shrinkSession) OpenStream() (protocol.Stream, error) {
	st, err := s.pipeSession.OpenStream()
	if err != nil {
		return nil, err
	}
	return shrinkConn{Conn: st.(net.Conn), shrinks: &s.shrinks}, nil
}

// The UDP edge lets a stream give back an empty receive buffer; the wrapper
// that holds the stream's slots must pass that on.
func TestLimitedStreamPassesShrinkOn(t *testing.T) {
	under := &shrinkSession{}
	ts := newTunnelSession("s1", 1, 0, under, 4)
	ts.user = newUserStreams(4)
	s, err := ts.OpenStream()
	require.NoError(t, err)
	defer s.Close()
	sh, ok := s.(interface{ Shrink() })
	require.True(t, ok, "the stream of a limited session offers Shrink")
	sh.Shrink()
	assert.EqualValues(t, 1, under.shrinks.Load())

	// The real yamux stream has the method, so it reaches yamux.
	real, _ := yamuxPair(t, 4)
	rs, err := real.OpenStream()
	require.NoError(t, err)
	defer rs.Close()
	_, ok = rs.(interface{ Shrink() })
	require.True(t, ok)
	rs.(interface{ Shrink() }).Shrink()
}

// yamuxPair returns a server-side TunnelSession over a real yamux session and
// the client end.
func yamuxPair(t *testing.T, maxStreams int) (*TunnelSession, protocol.Session) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
	return newTunnelSession("s1", 1, 0, server, maxStreams), client
}

// Closing our end frees the semaphore slot, but a stream the peer has not
// closed yet still holds its buffers. It keeps counting until the peer is
// done, so a client cannot pile up half-closed streams without limit.
func TestOpenStreamCountsStreamsThePeerHasNotClosedYet(t *testing.T) {
	ts, client := yamuxPair(t, 2)

	s1, err := ts.OpenStream()
	require.NoError(t, err)
	s2, err := ts.OpenStream()
	require.NoError(t, err)
	p1, err := client.AcceptStream()
	require.NoError(t, err)
	p2, err := client.AcceptStream()
	require.NoError(t, err)

	require.NoError(t, s1.Close())
	require.NoError(t, s2.Close())
	for i := 0; i < 5; i++ {
		_, err = ts.OpenStream()
		require.ErrorIs(t, err, ErrTooManyStreams, "both streams are still open on the peer's side")
		time.Sleep(20 * time.Millisecond)
	}

	// The peer finishes one stream: exactly one more fits.
	require.NoError(t, p1.Close())
	var s3 protocol.Stream
	require.Eventually(t, func() bool {
		s3, err = ts.OpenStream()
		return err == nil
	}, waitFor, 20*time.Millisecond)
	_, err = ts.OpenStream()
	require.ErrorIs(t, err, ErrTooManyStreams)
	_ = s3.Close()
	_ = p2.Close()
}

// With a real session the control stream is not a data stream: the full
// limit is available for data.
func TestOpenStreamLimitDoesNotCountTheControlStream(t *testing.T) {
	ts, client := yamuxPair(t, 3)
	go func() {
		for {
			if _, err := client.AcceptStream(); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 3; i++ {
		_, err := ts.OpenStream()
		require.NoError(t, err, "data stream %d of 3", i+1)
	}
	_, err := ts.OpenStream()
	require.ErrorIs(t, err, ErrTooManyStreams)
}

func TestTunnelSessionExposesOwnerAndToken(t *testing.T) {
	ts := newTunnelSession("abc123", 42, 7, &pipeSession{}, 0)
	assert.Equal(t, "abc123", ts.ID())
	assert.Equal(t, int64(42), ts.UserIDValue())
	assert.Equal(t, int64(7), ts.TokenIDValue())
	assert.Equal(t, int64(7), ts.TokenID)
	assert.WithinDuration(t, time.Now(), ts.ConnectedAtValue(), 5*time.Second)

	select {
	case <-ts.Done():
		t.Fatal("a new session is not done")
	default:
	}
	require.NoError(t, ts.Close())
	require.NoError(t, ts.Close())
	select {
	case <-ts.Done():
	default:
		t.Fatal("Close must mark the session done")
	}
}
