package acceptor

import (
	"context"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"weak"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// trackedConn is the server's connection as its yamux session holds it.
// Nothing else holds it, so a weak pointer to it shows when the closed
// session has become unreachable.
type trackedConn struct {
	io.ReadWriteCloser
	once   sync.Once
	closed chan struct{}
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.ReadWriteCloser.Close()
}

// releaseServer is an acceptor in database mode over in-memory pipes whose
// sessions hand out weak pointers to their connections. ok decides the
// logins.
func releaseServer(t *testing.T, ok bool, tweak func(*protocol.ServerOptions), wrap func(protocol.Session) protocol.Session) (*Acceptor, *pipeListener, *lockedBuffer, chan *trackedConnRef) {
	t.Helper()
	opts := dbModeOpts(registry.New())
	logger, logs := captureLogger()
	opts.Logger = logger
	acc := New(opts)
	v := &scriptedVerifier{answer: func(context.Context, int) (int64, int64, bool) { return 7, 70, ok }}
	acc.verifyToken = v.verify
	refs := make(chan *trackedConnRef, 4)
	acc.newSession = func(c io.ReadWriteCloser, o protocol.ServerOptions) (protocol.Session, error) {
		tc := &trackedConn{ReadWriteCloser: c, closed: make(chan struct{})}
		refs <- &trackedConnRef{ptr: weak.Make(tc), closed: tc.closed}
		if tweak != nil {
			tweak(&o)
		}
		sess, err := protocol.NewServerSessionWithOptions(tc, o)
		if err == nil && wrap != nil {
			sess = wrap(sess)
		}
		return sess, err
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
	return acc, ln, logs, refs
}

// trackedConnRef is what a test keeps of a session's connection.
type trackedConnRef struct {
	ptr    weak.Pointer[trackedConn]
	closed chan struct{}
}

// requireReleased waits until the session has closed its connection and
// then until the connection, and with it the session, is gone from memory.
// It allows two seconds: a close timer that a stream of the session armed
// would keep the session reachable for yamux's StreamCloseTimeout, five
// minutes.
func requireReleased(t *testing.T, refs chan *trackedConnRef) {
	t.Helper()
	var ref *trackedConnRef
	select {
	case ref = <-refs:
	case <-time.After(waitFor):
		t.Fatal("no session was made")
	}
	select {
	case <-ref.closed:
	case <-time.After(waitFor):
		t.Fatal("the session did not close its connection")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		runtime.GC()
		if ref.ptr.Value() == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the closed session is still reachable: a stream of it has a close timer pending")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A connection whose hello is refused ends with its session still up. The
// control stream must not be closed before the session: yamux's Stream.Close
// on an established stream arms a five-minute timer that neither its
// forceClose nor Session.Close stops, and that keeps the whole closed
// session in memory. Outsiders can make such connections at the rate of
// handshakes.
func TestAConnectionWithARefusedHelloIsReleased(t *testing.T) {
	_, ln, _, refs := releaseServer(t, false, nil, nil)
	c, _ := pipeClient(t, ln)
	assert.Equal(t, "invalid token", c.hello("twbl_some_token").Error)
	requireReleased(t, refs)
}

// The guard against a second stream closes the session; the extra stream is
// not closed before it, which would arm such a timer as well. (The frame
// guard's stream rule is off: it would end the connection before the
// acceptor's guard sees the stream.)
func TestASessionClosedForASecondStreamIsReleased(t *testing.T) {
	_, ln, logs, refs := releaseServer(t, true, func(o *protocol.ServerOptions) { o.PeerStreams = -1 }, nil)
	c, _ := pipeClient(t, ln)
	require.Empty(t, c.hello("twbl_some_token").Error)
	c.openEnding()
	requireReleased(t, refs)
	assert.Equal(t, 1, strings.Count(logs.String(), "client opened a second stream"), logs.String())
	assert.NotContains(t, logs.String(), "the peer did not take a new stream in time", "the accept succeeded")
}

// recordingSession hands the test the first stream the server accepts: the
// control stream.
type recordingSession struct {
	protocol.Session
	accepted chan protocol.Stream
}

func (s *recordingSession) AcceptStream() (protocol.Stream, error) {
	st, err := s.Session.AcceptStream()
	if err == nil {
		select {
		case s.accepted <- st:
		default:
		}
	}
	return st, err
}

// A client that leaves data in the control stream: once the connection has
// ended, nothing of it is left in the stream's receive buffer, where a
// closed session that yamux still keeps (a close timer of another stream)
// would hold it.
func TestAnEndedSessionLeavesNoControlDataBehind(t *testing.T) {
	accepted := make(chan protocol.Stream, 1)
	acc, ln, _, _ := releaseServer(t, false, nil, func(s protocol.Session) protocol.Session {
		return &recordingSession{Session: s, accepted: accepted}
	})
	c, _ := pipeClient(t, ln)
	require.NoError(t, c.send(protocol.TypeHello, protocol.Hello{Token: "twbl_some_token", ClientVersion: "test", OS: "test"}))
	// More control data than the server reads before it refuses the hello.
	_, err := c.ctrl.Write(make([]byte, 64<<10))
	require.NoError(t, err)
	env, err := c.recv(waitFor)
	require.NoError(t, err)
	require.Equal(t, protocol.TypeHelloAck, env.Type)
	var ctrl protocol.Stream
	select {
	case ctrl = <-accepted:
	case <-time.After(waitFor):
		t.Fatal("the control stream was not accepted")
	}
	// The connection has ended when its slot among the unauthenticated
	// connections is back (the last thing handleConn does).
	require.Eventually(t, func() bool {
		acc.unauth.mu.Lock()
		defer acc.unauth.mu.Unlock()
		return acc.unauth.total == 0
	}, waitFor, time.Millisecond)
	n, err := ctrl.Read(make([]byte, 128<<10))
	assert.Zero(t, n, "control data left in the stream's buffer")
	assert.ErrorIs(t, err, io.EOF)
}

// The acceptor's guard against a second stream logs through the limited
// logger: it is reachable before the login, one line per connection would
// let outsiders write the log at the rate of handshakes. Each connection is
// counted.
func TestTheSecondStreamWarningIsLimited(t *testing.T) {
	_, ln, logs, refs := releaseServer(t, false, func(o *protocol.ServerOptions) { o.PeerStreams = -1 }, nil)
	var m dto.Metric
	require.NoError(t, metrics.RequestTotal.WithLabelValues("tunnel", "second_stream").Write(&m))
	before := m.GetCounter().GetValue()
	const conns = 3
	for i := 0; i < conns; i++ {
		c, _ := pipeClient(t, ln)
		c.openEnding() // before any hello
	}
	for i := 0; i < conns; i++ {
		select {
		case ref := <-refs:
			select {
			case <-ref.closed:
			case <-time.After(waitFor):
				t.Fatal("a connection with a second stream was not closed")
			}
		case <-time.After(waitFor):
			t.Fatal("no session was made")
		}
	}
	require.NoError(t, metrics.RequestTotal.WithLabelValues("tunnel", "second_stream").Write(&m))
	assert.Equal(t, before+conns, m.GetCounter().GetValue())
	assert.Equal(t, 1, strings.Count(logs.String(), "client opened a second stream"), logs.String())
}
