package edgeudp

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// fullSocket is a UDP socket whose send buffer is full: a write waits until
// the write deadline passes, or for ever without one.
type fullSocket struct {
	*fakePacketConn
	attempts atomic.Int32

	mu       sync.Mutex
	deadline time.Time
}

func (s *fullSocket) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadline = t
	return nil
}

func (s *fullSocket) WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error) {
	s.attempts.Add(1)
	for {
		s.mu.Lock()
		d := s.deadline
		s.mu.Unlock()
		if !d.IsZero() && !time.Now().Before(d) {
			return 0, os.ErrDeadlineExceeded
		}
		select {
		case <-s.closed:
			return 0, net.ErrClosed
		case <-time.After(time.Millisecond):
		}
	}
}

// The backend's replies are read from the stream also while the socket
// cannot send them: they are dropped instead. A reader that waited for the
// socket would leave the stream's receive window, up to 256 KiB, sitting in
// the server's memory, for every flow of the port.
func TestRepliesAreReadAndDroppedWhileTheSocketCannotSend(t *testing.T) {
	logs := &logCapture{}
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40010, 40010), ReplyCredit: -1,
		IdleTimeout: time.Minute, SweepInterval: time.Minute, Logger: slog.New(logs)})
	conn, feed := feedSocket(t)
	sock := &fullSocket{fakePacketConn: conn}
	mgr.listen = func(int) (packetConn, error) { return sock, nil }
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	feed <- datagram{[]byte("hello"), netip.MustParseAddrPort("192.0.2.1:4000")}
	st, _ := acceptFlow(t, sess)
	before := requestCount(t, "send_buffer_full")

	// net.Pipe has no buffer: each write returns only once the edge has read
	// the datagram.
	const replies = 1000
	reply := make([]byte, 1024)
	done := make(chan error, 1)
	go func() {
		for i := 0; i < replies; i++ {
			if err := protocol.WriteDatagram(st, reply); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(6 * time.Second):
		t.Fatal("the edge stopped reading the backend's replies while the socket could not send")
	}

	require.Less(t, int(sock.attempts.Load()), replies/2, "after a write that timed out, replies are dropped without waiting")
	// The backend's last write returns once the edge has read the reply; the
	// edge counts it when it has dropped it, after up to one write's time.
	require.Eventually(t, func() bool { return requestCount(t, "send_buffer_full") == before+replies },
		time.Second, time.Millisecond, "every reply was dropped and counted")
	// A reply counted twice would be counted at the latest one wait and one
	// write later.
	time.Sleep(2 * (replyTurnWait + replyWriteTimeout))
	require.Equal(t, before+replies, requestCount(t, "send_buffer_full"), "no reply was counted twice")
	onlyFlow(t, mgr, port) // the flow is still there: a full send buffer does not end it
	// The port starting to drop is logged, through the limiter: once in the
	// few seconds of this test.
	require.Equal(t, 1, logs.count(slog.LevelWarn, "udp replies dropped"))
}

// slowSocket is a UDP socket under load: every write takes delay and then
// succeeds, unless the write deadline passes first.
type slowSocket struct {
	*fakePacketConn
	delay time.Duration
	sent  atomic.Int32

	mu       sync.Mutex
	deadline time.Time
}

func (s *slowSocket) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadline = t
	return nil
}

func (s *slowSocket) WriteToUDPAddrPort(b []byte, _ netip.AddrPort) (int, error) {
	done := time.Now().Add(s.delay)
	s.mu.Lock()
	d := s.deadline
	s.mu.Unlock()
	if !d.IsZero() && d.Before(done) {
		time.Sleep(time.Until(d))
		return 0, os.ErrDeadlineExceeded
	}
	time.Sleep(s.delay)
	s.sent.Add(1)
	return len(b), nil
}

// A socket that is slow but healthy (a write takes 15 ms because the host is
// busy or its egress is limited) loses no reply: the write may wait longer.
func TestASlowButHealthySocketLosesNoReply(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40012, 40012), ReplyCredit: -1,
		IdleTimeout: time.Minute, SweepInterval: time.Minute})
	conn, feed := feedSocket(t)
	sock := &slowSocket{fakePacketConn: conn, delay: 15 * time.Millisecond}
	mgr.listen = func(int) (packetConn, error) { return sock, nil }
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	feed <- datagram{[]byte("hello"), netip.MustParseAddrPort("192.0.2.1:4000")}
	st, _ := acceptFlow(t, sess)
	before := requestCount(t, "send_buffer_full")
	const replies = 40
	for i := 0; i < replies; i++ {
		require.NoError(t, protocol.WriteDatagram(st, []byte("reply")))
	}
	require.Eventually(t, func() bool { return sock.sent.Load() == replies }, 6*time.Second, time.Millisecond,
		"every reply is sent")
	assert.Equal(t, before, requestCount(t, "send_buffer_full"), "none is dropped")
}

// shrinkStream counts the calls of Shrink, the method by which a yamux
// stream gives back an empty receive buffer.
type shrinkStream struct {
	net.Conn
	shrinks *atomic.Int32
}

func (s shrinkStream) Shrink() { s.shrinks.Add(1) }

// A yamux stream keeps its receive buffer at the largest size a burst of
// replies made it grow to. The edge lets the stream give it back once it has
// read everything.
func TestReplyStreamGivesBackItsEmptyBuffer(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40011, 40011), IdleTimeout: time.Minute, SweepInterval: time.Minute})
	conn, feed := feedSocket(t)
	sent := &atomic.Int32{}
	conn.sent = sent
	mgr.listen = func(int) (packetConn, error) { return conn, nil }
	sess := newScriptSession()
	shrinks := &atomic.Int32{}
	sess.wrap = func(s protocol.Stream) protocol.Stream { return shrinkStream{Conn: s.(net.Conn), shrinks: shrinks} }
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	feed <- datagram{[]byte("hello"), netip.MustParseAddrPort("192.0.2.1:4000")}
	st, _ := acceptFlow(t, sess)
	for i := 0; i < 3; i++ {
		require.NoError(t, protocol.WriteDatagram(st, []byte("reply")))
	}
	require.Eventually(t, func() bool { return sent.Load() == 3 && shrinks.Load() >= 3 }, 6*time.Second, time.Millisecond,
		"sent %d, shrinks %d", sent.Load(), shrinks.Load())
}
