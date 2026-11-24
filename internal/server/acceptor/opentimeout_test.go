package acceptor

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

// stallConn is the tunnel client's end of a connection: while it is shut,
// the client does not read it, so the server's writes to it block.
type stallConn struct {
	net.Conn
	mu   sync.Mutex
	open *sync.Cond
	shut bool
}

func (g *stallConn) Read(p []byte) (int, error) {
	g.mu.Lock()
	for g.shut {
		g.open.Wait()
	}
	g.mu.Unlock()
	return g.Conn.Read(p)
}

func (g *stallConn) set(shut bool) {
	g.mu.Lock()
	g.shut = shut
	g.mu.Unlock()
	g.open.Broadcast()
}

// pipeClient connects a tunnel client to the acceptor over an in-memory pipe
// whose client end can stop reading.
func pipeClient(t *testing.T, ln *pipeListener) (*client, *stallConn) {
	t.Helper()
	c1, c2 := net.Pipe()
	ln.conns <- c2
	g := &stallConn{Conn: c1}
	g.open = sync.NewCond(&g.mu)
	sess, err := protocol.NewClientSession(g)
	require.NoError(t, err)
	t.Cleanup(func() {
		g.set(false) // first: yamux's Close waits for its reader
		_ = c1.Close()
		_ = sess.Close()
	})
	ctrl, err := sess.OpenStream()
	require.NoError(t, err)
	return &client{t: t, conn: g, sess: sess, ctrl: ctrl}, g
}

// openTimeoutServer is an acceptor in database mode over in-memory pipes
// with a TCP edge, whose sessions give up a write after writeTimeout.
func openTimeoutServer(t *testing.T, writeTimeout time.Duration, tweak func(*protocol.ServerOptions)) (*Acceptor, *pipeListener, *registry.Registry, *lockedBuffer) {
	t.Helper()
	low, high := testports.FreeTCPRange(t, 2)
	reg := registry.New()
	opts := dbModeOpts(reg)
	opts.TCPEdge = edgetcp.NewWithOptions(edgetcp.Options{BindHost: "127.0.0.1", Pool: edgetcp.NewPool(low, high)})
	logger, logs := captureLogger()
	opts.Logger = logger
	acc := New(opts)
	v := &scriptedVerifier{answer: func(context.Context, int) (int64, int64, bool) { return 7, 70, true }}
	acc.verifyToken = v.verify
	acc.newSession = func(c io.ReadWriteCloser, o protocol.ServerOptions) (protocol.Session, error) {
		o.ConnectionWriteTimeout = writeTimeout
		if tweak != nil {
			tweak(&o)
		}
		return protocol.NewServerSessionWithOptions(c, o)
	}
	ln := newPipeListener()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = acc.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		<-done
	})
	return acc, ln, reg, logs
}

// openTimeoutCount reads tunneld_request_total{type="tunnel",status="open_timeout"}.
func openTimeoutCount(t *testing.T) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, metrics.RequestTotal.WithLabelValues("tunnel", "open_timeout").Write(&m))
	return m.GetCounter().GetValue()
}

// yamux's OpenStream registers the new stream in the
// session before it sends the SYN, and when that send runs out of the
// connection write timeout (the client does not read its connection) it
// returns an error and leaves the stream in the session, where the client
// can later accept it and fill a window that nothing on the server reads or
// closes. A session whose client does not take a new stream in time is
// closed instead, as one that failed a keep-alive: its registration, its
// port and every place it held are gone. A new session of the same client
// works. (The shipped tunnel command does not reconnect on its own: it ends
// with its session, and its owner or a supervisor starts it again.)
func TestASessionWhoseClientDoesNotTakeANewStreamInTimeIsClosed(t *testing.T) {
	const writeTimeout = 200 * time.Millisecond
	acc, ln, reg, logs := openTimeoutServer(t, writeTimeout, nil)
	before := openTimeoutCount(t)

	c, gate := pipeClient(t, ln)
	require.Empty(t, c.hello("twbl_some_token").Error)
	tcp := c.registerTCP(0)
	require.Empty(t, tcp.Error)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(tcp.Port))
	require.Len(t, reg.SnapshotAll(), 1)

	gate.set(true) // the client stops reading its connection
	var visitors []net.Conn
	for i := 0; i < 3; i++ {
		v, err := net.DialTimeout("tcp", addr, 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = v.Close() })
		visitors = append(visitors, v)
	}
	// The opens of the edge fail after the write timeout: the visitors are
	// closed and the session with them.
	for _, v := range visitors {
		_ = v.SetReadDeadline(time.Now().Add(waitFor))
		n, err := v.Read(make([]byte, 1))
		require.Zero(t, n)
		require.Error(t, err)
		require.False(t, isTimeout(err), "the visitor was not answered")
	}
	require.Eventually(t, func() bool { return len(reg.SnapshotAll()) == 0 }, waitFor, 10*time.Millisecond,
		"the session whose client did not take a new stream is still registered")
	require.Eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
		}
		return err != nil
	}, waitFor, 20*time.Millisecond, "the session's TCP port is still open")
	require.Zero(t, acc.userStreams.held(7), "the user's stream slots are not back")
	assert.Equal(t, before+1, openTimeoutCount(t), "the session is counted once, however many of its opens failed")
	assert.Contains(t, logs.String(), "closed=1", "the line counts closed sessions")
	assert.Equal(t, 1, strings.Count(logs.String(), "the client did not take a new stream in time"), logs.String())

	// The honest variant: the link was stalled; the client is started again
	// with a new session, and its tunnel works again.
	gate.set(false)
	c2, _ := pipeClient(t, ln)
	require.Empty(t, c2.hello("twbl_some_token").Error)
	tcp2 := c2.registerTCP(0)
	require.Empty(t, tcp2.Error)
	served := make(chan error, 1)
	go func() {
		st, err := c2.sess.AcceptStream()
		if err != nil {
			served <- err
			return
		}
		if _, err := protocol.ReadStreamHeader(st); err != nil {
			served <- err
			return
		}
		_, err = st.Write([]byte("hello"))
		served <- err
	}()
	v, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tcp2.Port)), 5*time.Second)
	require.NoError(t, err)
	defer v.Close()
	_ = v.SetReadDeadline(time.Now().Add(waitFor))
	buf := make([]byte, 5)
	_, err = io.ReadFull(v, buf)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buf))
	require.NoError(t, <-served)
	require.Len(t, reg.SnapshotAll(), 1)
}

// The client opens a second stream while it does not read its connection.
// yamux's AcceptStream registers the stream, then its ACK runs out of the
// connection write timeout: AcceptStream fails with the stream registered
// and the session alive. A guard against extra streams that took that error
// for the end of the session and stopped accepting would let the client park
// the 32 streams of the accept backlog, each with a full window, for the
// life of the session. So the session is closed: its registration, its port
// and the user's places are gone.
//
// The frame guard below yamux ends the connection at the second stream
// before yamux registers it; this test switches that rule off to test the
// acceptor's own guard, the second line.
func TestASessionWhoseClientDoesNotTakeTheAckOfASecondStreamIsClosed(t *testing.T) {
	const writeTimeout = 200 * time.Millisecond
	acc, ln, reg, logs := openTimeoutServer(t, writeTimeout, func(o *protocol.ServerOptions) { o.PeerStreams = -1 })
	c, gate := pipeClient(t, ln)
	require.Empty(t, c.hello("twbl_some_token").Error)
	tcp := c.registerTCP(0)
	require.Empty(t, tcp.Error)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(tcp.Port))
	require.Len(t, reg.SnapshotAll(), 1)

	// The client stops reading. A read of its yamux that already waits on
	// the pipe takes one more write; the pong of a control ping then blocks
	// the server's send loop, as a full socket buffer would.
	gate.set(true)
	require.NoError(t, c.send("ping", nil))
	time.Sleep(50 * time.Millisecond)
	_, err := c.sess.OpenStream() // its SYN reaches the server, its ACK cannot leave
	require.NoError(t, err)
	time.Sleep(3 * writeTimeout)
	gate.set(false)

	require.Eventually(t, func() bool { return len(reg.SnapshotAll()) == 0 }, waitFor, 10*time.Millisecond,
		"the session whose client did not take the ACK of its second stream is still registered")
	require.Eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
		}
		return err != nil
	}, waitFor, 20*time.Millisecond, "the session's TCP port is still open")
	require.Zero(t, acc.userStreams.held(7), "the user's stream slots are not back")
	assert.Equal(t, 1, strings.Count(logs.String(), "client opened a second stream"), logs.String())
	assert.Contains(t, logs.String(), "the peer did not take a new stream in time", "the accept's ACK timed out")
}

// A client that opens a second stream loses its connection at the frame
// guard below yamux, before the session registers the stream: the session
// is gone, counted as second_stream, with one limited log line.
func TestASecondStreamEndsTheConnectionBelowYamux(t *testing.T) {
	_, ln, reg, logs := openTimeoutServer(t, time.Second, nil)
	var m dto.Metric
	require.NoError(t, metrics.RequestTotal.WithLabelValues("tunnel", "second_stream").Write(&m))
	before := m.GetCounter().GetValue()

	c, _ := pipeClient(t, ln)
	require.Empty(t, c.hello("twbl_some_token").Error)
	require.Len(t, reg.SnapshotAll(), 1)
	// The server ends the connection as soon as the SYN arrives. yamux's
	// OpenStream waits for its send loop to report the frame written or for
	// the session's end, whichever it sees first: over a pipe the server can
	// have read the frame and closed the connection before the send loop
	// reports, so the open may fail with the session's end. That the SYN got
	// through is shown by the count and the log line below.
	_, err := c.sess.OpenStream()
	if err != nil {
		require.ErrorIs(t, err, yamux.ErrSessionShutdown)
	}
	require.Eventually(t, func() bool { return len(reg.SnapshotAll()) == 0 }, waitFor, 10*time.Millisecond,
		"the session of a client that opened a second stream is still registered")
	require.NoError(t, metrics.RequestTotal.WithLabelValues("tunnel", "second_stream").Write(&m))
	assert.Equal(t, before+1, m.GetCounter().GetValue())
	assert.Equal(t, 1, strings.Count(logs.String(), "client opened a second stream, closing tunnel connection"), logs.String())
}

// leftOpenSession is a protocol.Session whose opens wait until release is
// closed and then fail as yamux's do when the client does not take the new
// stream in time.
type leftOpenSession struct {
	waiting atomic.Int32
	release chan struct{}
}

func (s *leftOpenSession) OpenStream() (protocol.Stream, error) {
	s.waiting.Add(1)
	<-s.release
	return nil, fmt.Errorf("%w: connection write timeout", protocol.ErrStreamLeftOpen)
}

func (s *leftOpenSession) AcceptStream() (protocol.Stream, error) { return nil, io.EOF }
func (s *leftOpenSession) Close() error                           { return nil }

// Many opens of one session fail at once (up to the 32 SYNs yamux lets wait
// for an ACK): the session is closed once, and counted and logged once, by
// the open whose Close closed it.
func TestManyFailedOpensOfOneSessionCountAsOneClosedSession(t *testing.T) {
	under := &leftOpenSession{release: make(chan struct{})}
	ts := newTunnelSession("s1", 7, 70, under, 0)
	var noted atomic.Int32
	ts.onOpenTimeout = func() { noted.Add(1) }
	const opens = 8
	var wg sync.WaitGroup
	for i := 0; i < opens; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ts.OpenStream()
			assert.ErrorIs(t, err, protocol.ErrStreamLeftOpen)
		}()
	}
	require.Eventually(t, func() bool { return under.waiting.Load() == opens }, waitFor, time.Millisecond)
	close(under.release)
	wg.Wait()
	require.True(t, isClosed(ts))
	require.Equal(t, int32(1), noted.Load(), "one closed session")
}

// The streams a session hands out tell when the session has ended, so that
// a paced drain of a retired stream reads the rest at full speed then
// (edgeguard.SessionDone).
func TestAStreamOfTheSessionTellsWhenTheSessionHasEnded(t *testing.T) {
	ts, client := yamuxPair(t, 4)
	st, err := ts.OpenStream()
	require.NoError(t, err)
	go func() { _, _ = client.AcceptStream() }()
	done := edgeguard.SessionDone(st)
	require.NotNil(t, done, "the stream cannot tell its session's end")
	select {
	case <-done:
		t.Fatal("ended before the session")
	default:
	}
	require.NoError(t, ts.Close())
	select {
	case <-done:
	case <-time.After(waitFor):
		t.Fatal("the end of the session is not seen")
	}
}

// Errors of an open that leave nothing behind keep their handling: the
// per-session and the per-user limit refuse the stream, a closed session
// refuses it; none of them closes the session or counts as a timeout.
func TestErrorsThatLeaveNoStreamDoNotCloseTheSession(t *testing.T) {
	t.Run("the per-session limit", func(t *testing.T) {
		ts, _ := yamuxPair(t, 1)
		var timedOut atomic.Int32
		ts.onOpenTimeout = func() { timedOut.Add(1) }
		_, err := ts.OpenStream()
		require.NoError(t, err)
		_, err = ts.OpenStream()
		require.ErrorIs(t, err, ErrTooManyStreams)
		require.False(t, isClosed(ts))
		require.Zero(t, timedOut.Load())
	})
	t.Run("the per-user limit", func(t *testing.T) {
		ts, _ := yamuxPair(t, 0)
		ts.user = newUserStreams(1)
		var timedOut atomic.Int32
		ts.onOpenTimeout = func() { timedOut.Add(1) }
		_, err := ts.OpenStream()
		require.NoError(t, err)
		_, err = ts.OpenStream()
		require.ErrorIs(t, err, ErrTooManyUserStreams)
		require.False(t, isClosed(ts))
		require.Zero(t, timedOut.Load())
	})
	t.Run("a session that is closed", func(t *testing.T) {
		ts, _ := yamuxPair(t, 0)
		var timedOut atomic.Int32
		ts.onOpenTimeout = func() { timedOut.Add(1) }
		require.NoError(t, ts.Close())
		_, err := ts.OpenStream()
		require.Error(t, err)
		require.Zero(t, timedOut.Load())
	})
}
