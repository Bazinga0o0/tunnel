package edgetcp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

// --- helpers ---------------------------------------------------------------

// scriptSession is a tunnel session whose OpenStream can be made to block,
// fail or panic. The backend end of every opened stream arrives on streams.
type scriptSession struct {
	streams  chan protocol.Stream
	openHook func(n int32) error                   // n counts OpenStream calls from 1
	wrap     func(protocol.Stream) protocol.Stream // optional: replaces the edge's end of the stream
	opens    atomic.Int32
}

func newScriptSession() *scriptSession {
	return &scriptSession{streams: make(chan protocol.Stream, 1024)}
}

func (s *scriptSession) OpenStream() (protocol.Stream, error) {
	n := s.opens.Add(1)
	if s.openHook != nil {
		if err := s.openHook(n); err != nil {
			return nil, err
		}
	}
	a, b := protocol.PipeStream()
	s.streams <- a
	if s.wrap != nil {
		b = s.wrap(b)
	}
	return b, nil
}

// closeBackends closes the backend end of every stream that no test took.
func (s *scriptSession) closeBackends() {
	for {
		select {
		case st := <-s.streams:
			_ = st.Close()
		default:
			return
		}
	}
}

// acceptStream returns the backend end of the next stream after reading its
// header. Reads and writes on it fail after five seconds so that a broken
// test ends instead of hanging.
func acceptStream(t *testing.T, s *scriptSession) (net.Conn, *protocol.StreamHeader) {
	t.Helper()
	select {
	case st := <-s.streams:
		c := st.(net.Conn)
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
		hdr, err := protocol.ReadStreamHeader(c)
		require.NoError(t, err)
		return c, hdr
	case <-time.After(6 * time.Second):
		t.Fatal("no stream was opened towards the backend")
		return nil, nil
	}
}

// testPorts returns a pool of n free TCP ports and the ports themselves. No
// test binds a fixed port number: the system reserves port ranges that change
// from boot to boot. Tests pass the ports to Open as the preferred port.
func testPorts(t *testing.T, n int) (*Pool, []int) {
	t.Helper()
	low, high := testports.FreeTCPRange(t, n)
	ports := make([]int, 0, n)
	for p := low; p <= high; p++ {
		ports = append(ports, p)
	}
	return NewPool(low, high), ports
}

func dial(t *testing.T, port int) *net.TCPConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 10*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c.(*net.TCPConn)
}

// expectClosed asserts that the peer closes c within the given time without
// sending anything first.
func expectClosed(t *testing.T, c net.Conn, within time.Duration, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(within))
	n, err := c.Read(make([]byte, 1))
	require.Zero(t, n, what)
	require.Error(t, err, what)
	var ne net.Error
	require.False(t, errors.As(err, &ne) && ne.Timeout(), "%s: still open after %v", what, within)
}

// expectOpen asserts that nothing arrives on c and c stays open for d.
func expectOpen(t *testing.T, c net.Conn, d time.Duration, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	n, err := c.Read(make([]byte, 1))
	require.Zero(t, n, what)
	var ne net.Error
	require.True(t, errors.As(err, &ne) && ne.Timeout(), "%s: got %v", what, err)
	_ = c.SetReadDeadline(time.Time{})
}

// exchange sends msg from one end to the other and checks its arrival.
func exchange(t *testing.T, from io.Writer, to net.Conn, msg string) {
	t.Helper()
	_, err := from.Write([]byte(msg))
	require.NoError(t, err)
	buf := make([]byte, len(msg))
	_ = to.SetReadDeadline(time.Now().Add(8 * time.Second))
	_, err = io.ReadFull(to, buf)
	require.NoError(t, err)
	require.Equal(t, msg, string(buf))
	_ = to.SetReadDeadline(time.Time{})
}

// requestCount reads tunneld_request_total{type="tcp",status=status}.
func requestCount(t *testing.T, status string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != "tunneld_request_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["type"] == "tcp" && labels["status"] == status {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// logCapture is a slog.Handler that keeps every record.
type logCapture struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler       { return c }
func (c *logCapture) WithGroup(string) slog.Handler            { return c }
func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, r)
	return nil
}

func (c *logCapture) count(level slog.Level, msgPart string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range c.recs {
		if r.Level == level && strings.Contains(r.Message, msgPart) {
			n++
		}
	}
	return n
}

// yamuxPair is a real yamux session over an in-memory connection. server is
// what the edge opens streams on, client plays the tunnel client.
func yamuxPair(t *testing.T) (server, client protocol.Session) {
	t.Helper()
	c1, c2 := net.Pipe()
	server, err := protocol.NewServerSession(c1)
	require.NoError(t, err)
	client, err = protocol.NewClientSession(c2)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	return server, client
}

// acceptYamux returns the tunnel client's end of the next stream after
// reading its header.
func acceptYamux(t *testing.T, client protocol.Session) (protocol.Stream, *protocol.StreamHeader) {
	t.Helper()
	type result struct {
		st  protocol.Stream
		hdr *protocol.StreamHeader
		err error
	}
	ch := make(chan result, 1)
	go func() {
		st, err := client.AcceptStream()
		if err != nil {
			ch <- result{err: err}
			return
		}
		hdr, err := protocol.ReadStreamHeader(st)
		ch <- result{st, hdr, err}
	}()
	select {
	case r := <-ch:
		require.NoError(t, r.err)
		return r.st, r.hdr
	case <-time.After(6 * time.Second):
		t.Fatal("no stream reached the tunnel client")
		return nil, nil
	}
}

// --- connections do not outlive their listener ---------------------------------

func TestCloseEndsAcceptedConnections(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)

	v1, v2 := dial(t, port), dial(t, port)
	b1, hdr := acceptStream(t, sess)
	b2, _ := acceptStream(t, sess)
	require.Equal(t, protocol.StreamTypeTCP, hdr.StreamType)
	require.Equal(t, "127.0.0.1", hdr.RemoteIP)
	require.Equal(t, port, hdr.PublicPort)
	exchange(t, v1, b1, "ping")
	exchange(t, b1, v1, "pong")

	mgr.Close(port)

	expectClosed(t, v1, 6*time.Second, "visitor connection 1 after Close")
	expectClosed(t, v2, 6*time.Second, "visitor connection 2 after Close")
	expectClosed(t, b1, 6*time.Second, "backend stream 1 after Close")
	expectClosed(t, b2, 6*time.Second, "backend stream 2 after Close")
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)

	// The port is free again.
	port2, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	mgr.Close(port2)
	mgr.Close(port2) // closing twice is harmless
}

// A narrow window: a connection is accepted, the listener is
// closed while the stream for it is still being opened.
func TestCloseWhileStreamIsBeingOpened(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})

	entered := make(chan struct{})
	gate := make(chan struct{})
	sess := newScriptSession()
	sess.openHook = func(int32) error {
		close(entered)
		<-gate
		return nil
	}
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)

	v := dial(t, port)
	select {
	case <-entered:
	case <-time.After(6 * time.Second):
		t.Fatal("the connection did not reach OpenStream")
	}
	mgr.Close(port)
	close(gate)

	expectClosed(t, v, 6*time.Second, "visitor connection accepted before Close")
	select {
	case st := <-sess.streams:
		c := st.(net.Conn)
		_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
		n, err := io.Copy(io.Discard, c)
		var ne net.Error
		require.False(t, errors.As(err, &ne) && ne.Timeout(), "the stream opened for the closed listener was left open")
		require.Zero(t, n, "the stream was put to use although its listener was closed")
	case <-time.After(6 * time.Second):
		t.Fatal("OpenStream did not complete")
	}
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// With a real yamux stream Close on the edge's side does not end the edge's
// own read: the backend must not be needed to get rid of the connection.
func TestCloseDoesNotDependOnTheBackendClosingItsStream(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})
	server, client := yamuxPair(t)
	port, err := mgr.Open(context.Background(), ports[0], server)
	require.NoError(t, err)

	v := dial(t, port)
	st, _ := acceptYamux(t, client)
	_, err = v.Write([]byte("hello"))
	require.NoError(t, err)
	buf := make([]byte, 5)
	_, err = io.ReadFull(st, buf)
	require.NoError(t, err)
	require.Equal(t, 1, mgr.limiter.Total())

	mgr.Close(port)
	expectClosed(t, v, 6*time.Second, "visitor connection after Close")
	// The backend keeps its end open and silent. The edge lets go regardless;
	// the stream holds its place in the total until it is gone.
	require.Eventually(t, func() bool { return mgr.limiter.Visitors() == 0 }, 6*time.Second, 5*time.Millisecond,
		"the connection handler is still waiting for the backend")
	require.Equal(t, 1, mgr.limiter.Total())
	require.NoError(t, st.Close())
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// --- panics --------------------------------------------------------------------

func TestPanicInOpenStreamDoesNotEndTheProcess(t *testing.T) {
	logs := &logCapture{}
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, Logger: slog.New(logs)})
	sess := newScriptSession()
	sess.openHook = func(n int32) error {
		if n == 1 {
			panic("boom in OpenStream")
		}
		return nil
	}
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := dial(t, port)
	expectClosed(t, v, 6*time.Second, "connection whose handler panicked")
	require.Eventually(t, func() bool { return logs.count(slog.LevelError, "panic recovered") == 1 },
		6*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)

	v2 := dial(t, port)
	b2, _ := acceptStream(t, sess)
	exchange(t, v2, b2, "still serving")
}

// panicStream panics on read or on the nth write.
type panicStream struct {
	net.Conn     // the stream; embedding the conn keeps its deadline methods
	onRead       bool
	panicOnWrite int32 // 1-based write that panics; 0 never
	writes       atomic.Int32
}

func (p *panicStream) Read(b []byte) (int, error) {
	if p.onRead {
		panic("boom in stream read")
	}
	return p.Conn.Read(b)
}

func (p *panicStream) Write(b []byte) (int, error) {
	if n := p.writes.Add(1); p.panicOnWrite != 0 && n >= p.panicOnWrite {
		panic("boom in stream write")
	}
	return p.Conn.Write(b)
}

func TestPanicInEitherCopyDirectionDoesNotEndTheProcess(t *testing.T) {
	for _, tc := range []struct {
		name   string
		wrap   func(protocol.Stream) protocol.Stream
		panics int // logged panics
	}{
		// The drain of the retired stream reads it too, and its panic is
		// recovered and logged as well.
		{"backend to visitor", func(s protocol.Stream) protocol.Stream { return &panicStream{Conn: s.(net.Conn), onRead: true} }, 2},
		// The stream header takes two writes (length, payload); the third write is visitor data.
		{"visitor to backend", func(s protocol.Stream) protocol.Stream { return &panicStream{Conn: s.(net.Conn), panicOnWrite: 3} }, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &logCapture{}
			pool, ports := testPorts(t, 1)
			mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, Logger: slog.New(logs)})
			sess := newScriptSession()
			sess.wrap = func(s protocol.Stream) protocol.Stream {
				if sess.opens.Load() == 1 {
					return tc.wrap(s)
				}
				return s
			}
			port, err := mgr.Open(context.Background(), ports[0], sess)
			require.NoError(t, err)
			defer mgr.Close(port)

			v := dial(t, port)
			b, _ := acceptStream(t, sess)
			go func() { _, _ = io.Copy(io.Discard, b) }()
			_, _ = v.Write([]byte("data that reaches the panicking write"))
			expectClosed(t, v, 6*time.Second, "connection whose copy panicked")
			require.Eventually(t, func() bool { return logs.count(slog.LevelError, "panic recovered") == tc.panics },
				6*time.Second, 5*time.Millisecond)
			require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)

			v2 := dial(t, port)
			b2, _ := acceptStream(t, sess)
			exchange(t, v2, b2, "still serving")
		})
	}
}

// --- limits ----------------------------------------------------------------------

func TestDefaultsAndDisabledSettings(t *testing.T) {
	pool := NewPool(40000, 40001)

	for _, def := range []*Manager{New(pool, nil), NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})} {
		require.Equal(t, 256, def.opts.MaxConnsPerTunnel)
		require.Equal(t, 64, def.opts.MaxConnsPerIP)
		require.Equal(t, 1000, def.opts.MaxConns)
		require.Equal(t, 30*time.Minute, def.opts.IdleTimeout)
	}

	set := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, MaxConnsPerTunnel: 7, MaxConnsPerIP: 3, MaxConns: 9, IdleTimeout: time.Second})
	require.Equal(t, 7, set.opts.MaxConnsPerTunnel)
	require.Equal(t, 3, set.opts.MaxConnsPerIP)
	require.Equal(t, 9, set.opts.MaxConns)
	require.Equal(t, time.Second, set.opts.IdleTimeout)

	// Negative disables; internally a disabled setting is zero.
	off := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, MaxConnsPerTunnel: -1, MaxConnsPerIP: -1, MaxConns: -1, IdleTimeout: -1})
	require.Zero(t, off.opts.MaxConnsPerTunnel)
	require.Zero(t, off.opts.MaxConnsPerIP)
	require.Zero(t, off.opts.MaxConns)
	require.Zero(t, off.opts.IdleTimeout)
}

// connect opens n visitor connections and waits until each has a stream.
func connect(t *testing.T, port int, sess *scriptSession, n int) (visitors []*net.TCPConn, backends []net.Conn) {
	t.Helper()
	for i := 0; i < n; i++ {
		v := dial(t, port)
		b, _ := acceptStream(t, sess)
		visitors = append(visitors, v)
		backends = append(backends, b)
	}
	return visitors, backends
}

func TestConnLimitPerTunnel(t *testing.T) {
	pool, ports := testPorts(t, 2)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, MaxConnsPerTunnel: 2, MaxConnsPerIP: 100, MaxConns: 100})
	sessA, sessB := newScriptSession(), newScriptSession()
	portA, err := mgr.Open(context.Background(), ports[0], sessA)
	require.NoError(t, err)
	defer mgr.Close(portA)
	portB, err := mgr.Open(context.Background(), ports[1], sessB)
	require.NoError(t, err)
	defer mgr.Close(portB)

	visitors, backends := connect(t, portA, sessA, 2)
	before := requestCount(t, "limit_tunnel")
	proxied := requestCount(t, "proxied")

	// The third connection to tunnel A is closed at once and gets no stream.
	expectClosed(t, dial(t, portA), 6*time.Second, "connection over the per-tunnel limit")
	require.Equal(t, before+1, requestCount(t, "limit_tunnel"))
	require.Equal(t, proxied, requestCount(t, "proxied"), "a refused connection is not counted as proxied")
	require.EqualValues(t, 2, sessA.opens.Load())
	require.Equal(t, 2, mgr.limiter.Total())

	// The connections inside the limit are unaffected, tunnel B has its own budget.
	exchange(t, visitors[0], backends[0], "a0")
	exchange(t, visitors[1], backends[1], "a1")
	connect(t, portB, sessB, 2)

	// A slot that is given back can be used again.
	require.NoError(t, visitors[0].Close())
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 3 }, 6*time.Second, 5*time.Millisecond)
	v, b := connect(t, portA, sessA, 1)
	exchange(t, v[0], b[0], "a2")
}

func TestConnLimitPerSourceIP(t *testing.T) {
	pool, ports := testPorts(t, 2)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, MaxConnsPerTunnel: 100, MaxConnsPerIP: 2, MaxConns: 100})
	sessA, sessB := newScriptSession(), newScriptSession()
	portA, err := mgr.Open(context.Background(), ports[0], sessA)
	require.NoError(t, err)
	defer mgr.Close(portA)
	portB, err := mgr.Open(context.Background(), ports[1], sessB)
	require.NoError(t, err)
	defer mgr.Close(portB)

	connect(t, portA, sessA, 2)
	before := requestCount(t, "limit_ip")
	expectClosed(t, dial(t, portA), 6*time.Second, "connection over the per-source limit")
	require.Equal(t, before+1, requestCount(t, "limit_ip"))
	require.EqualValues(t, 2, sessA.opens.Load())

	// The limit is per tunnel: the same source may connect to tunnel B.
	connect(t, portB, sessB, 2)
}

func TestConnLimitTotal(t *testing.T) {
	pool, ports := testPorts(t, 2)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, MaxConnsPerTunnel: 100, MaxConnsPerIP: 100, MaxConns: 3})
	sessA, sessB := newScriptSession(), newScriptSession()
	portA, err := mgr.Open(context.Background(), ports[0], sessA)
	require.NoError(t, err)
	defer mgr.Close(portA)
	portB, err := mgr.Open(context.Background(), ports[1], sessB)
	require.NoError(t, err)

	connect(t, portA, sessA, 2)
	connect(t, portB, sessB, 1)
	before := requestCount(t, "limit_total")
	expectClosed(t, dial(t, portA), 6*time.Second, "fourth connection overall")
	expectClosed(t, dial(t, portB), 6*time.Second, "fifth connection overall")
	require.Equal(t, before+2, requestCount(t, "limit_total"))
	require.EqualValues(t, 2, sessA.opens.Load())
	require.EqualValues(t, 1, sessB.opens.Load())

	// Closing tunnel B gives its connection back to the total.
	mgr.Close(portB)
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 2 }, 6*time.Second, 5*time.Millisecond)
	connect(t, portA, sessA, 1)
}

func TestDisabledConnLimits(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, MaxConnsPerTunnel: -1, MaxConnsPerIP: -1, MaxConns: -1})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	// More connections from one source than the per-IP default of 64 allows.
	connect(t, port, sess, 70)
}

func TestDefaultConnLimitPerSourceIPIs64(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	connect(t, port, sess, 64)
	before := requestCount(t, "limit_ip")
	expectClosed(t, dial(t, port), 6*time.Second, "connection 65 from one source")
	require.Equal(t, before+1, requestCount(t, "limit_ip"))
	require.EqualValues(t, 64, sess.opens.Load())
}

// --- idle timeout ------------------------------------------------------------------

func TestIdleConnectionIsClosed(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 400 * time.Millisecond})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := dial(t, port)
	b, _ := acceptStream(t, sess)
	exchange(t, v, b, "ping")
	start := time.Now() // before the last byte moves
	exchange(t, b, v, "pong")

	expectClosed(t, v, 6*time.Second, "idle visitor connection")
	require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond, "closed before the idle timeout")
	expectClosed(t, b, 6*time.Second, "backend stream of the idle connection")
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

func TestIdleTimeoutIsExtendedByActivityInEitherDirection(t *testing.T) {
	for _, tc := range []struct {
		name            string
		visitorIsSender bool
	}{
		{"visitor to backend", true},
		{"backend to visitor", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, ports := testPorts(t, 1)
			mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Second})
			sess := newScriptSession()
			port, err := mgr.Open(context.Background(), ports[0], sess)
			require.NoError(t, err)
			defer mgr.Close(port)

			v := dial(t, port)
			b, _ := acceptStream(t, sess)
			var from io.Writer = v
			var to net.Conn = b
			if !tc.visitorIsSender {
				from, to = b, v
			}

			// One byte every 100 ms for 2.5 s, two and a half times the timeout,
			// in one direction only. The other direction stays silent throughout.
			start := time.Now()
			for i := 0; time.Since(start) < 2500*time.Millisecond; i++ {
				exchange(t, from, to, "x")
				time.Sleep(100 * time.Millisecond)
			}

			// Once the traffic stops the connection is closed.
			expectClosed(t, v, 6*time.Second, "visitor connection after the traffic stopped")
		})
	}
}

func TestIdleTimeoutDisabled(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: -1})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := dial(t, port)
	b, _ := acceptStream(t, sess)
	expectOpen(t, v, 500*time.Millisecond, "connection without idle timeout")
	exchange(t, v, b, "still open")
}

// A real yamux stream keeps serving reads after the edge closed its side.
// The idle timeout has to end both directions on its own.
func TestIdleTimeoutEndsConnectionOverYamux(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 400 * time.Millisecond})
	server, client := yamuxPair(t)
	port, err := mgr.Open(context.Background(), ports[0], server)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := dial(t, port)
	st, _ := acceptYamux(t, client)
	_, err = v.Write([]byte("hello"))
	require.NoError(t, err)
	_, err = io.ReadFull(st, make([]byte, 5))
	require.NoError(t, err)

	// Neither side sends or closes anything.
	expectClosed(t, v, 6*time.Second, "idle visitor connection")
	require.Eventually(t, func() bool { return mgr.limiter.Visitors() == 0 }, 6*time.Second, 5*time.Millisecond,
		"the connection handler is still waiting for the backend")
	require.Equal(t, 1, mgr.limiter.Total(), "the stream the backend keeps open holds its place in the total")
	require.NoError(t, st.Close())
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// --- existing behaviour that must stay ---------------------------------------------

func TestHalfCloseFromVisitorStillDeliversTheReply(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})
	server, client := yamuxPair(t)
	port, err := mgr.Open(context.Background(), ports[0], server)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := dial(t, port)
	st, _ := acceptYamux(t, client)

	// The visitor sends its request and closes its write side.
	_, err = v.Write([]byte("request"))
	require.NoError(t, err)
	require.NoError(t, v.CloseWrite())

	// The backend reads until EOF, then answers and closes.
	got, err := io.ReadAll(st)
	require.NoError(t, err)
	require.Equal(t, "request", string(got))
	_, err = st.Write([]byte("reply"))
	require.NoError(t, err)
	require.NoError(t, st.Close())

	_ = v.SetReadDeadline(time.Now().Add(8 * time.Second))
	reply, err := io.ReadAll(v)
	require.NoError(t, err)
	require.Equal(t, "reply", string(reply))
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

func TestBackendCloseIsPassedOnAsEOF(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})
	server, client := yamuxPair(t)
	port, err := mgr.Open(context.Background(), ports[0], server)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := dial(t, port)
	st, _ := acceptYamux(t, client)
	_, err = st.Write([]byte("banner"))
	require.NoError(t, err)
	require.NoError(t, st.Close())

	_ = v.SetReadDeadline(time.Now().Add(8 * time.Second))
	got, err := io.ReadAll(v)
	require.NoError(t, err, "the visitor sees a clean end of stream")
	require.Equal(t, "banner", string(got))
}

// --- error logging -------------------------------------------------------------------

func TestOpenStreamFailureClosesConnectionAndIsLoggedOncePerInterval(t *testing.T) {
	logs := &logCapture{}
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, Logger: slog.New(logs)})
	sess := newScriptSession()
	sess.openHook = func(int32) error { return errors.New("session is gone") }
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	const attempts = 20
	for i := 0; i < attempts; i++ {
		expectClosed(t, dial(t, port), 6*time.Second, "connection without a stream")
	}
	require.EqualValues(t, attempts, sess.opens.Load())
	require.Equal(t, 1, logs.count(slog.LevelWarn, "open stream failed"),
		"%d failed opens within one interval produce one warning", attempts)
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

func TestStreamHeaderWriteFailureClosesConnection(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := dial(t, port)
	select {
	case st := <-sess.streams:
		require.NoError(t, st.Close()) // the backend goes away before it reads the header
	case <-time.After(6 * time.Second):
		t.Fatal("no stream was opened")
	}
	expectClosed(t, v, 6*time.Second, "connection whose stream died")
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// fakeListener is a listener whose Accept follows a script.
type fakeListener struct {
	// script decides what Accept number n (from 1) returns. block makes the
	// call wait until the listener is closed.
	script func(n int) (conn net.Conn, err error, block bool)

	mu     sync.Mutex
	calls  []time.Time
	once   sync.Once
	closed chan struct{}
}

func newFakeListener(script func(n int) (net.Conn, error, bool)) *fakeListener {
	return &fakeListener{script: script, closed: make(chan struct{})}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls = append(l.calls, time.Now())
	n := len(l.calls)
	l.mu.Unlock()

	conn, err, block := l.script(n)
	if block || n > 100000 { // the cap keeps a loop without backoff from eating memory
		<-l.closed
		return nil, net.ErrClosed
	}
	return conn, err
}

func (l *fakeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *fakeListener) callTimes() []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.calls...)
}

func TestAcceptErrorsBackOff(t *testing.T) {
	logs := &logCapture{}
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: NewPool(40010, 40010), Logger: slog.New(logs)})
	ln := newFakeListener(func(int) (net.Conn, error, bool) {
		return nil, errors.New("too many open files"), false
	})
	mgr.listen = func(int) (net.Listener, error) { return ln, nil }

	port, err := mgr.Open(context.Background(), 0, newScriptSession())
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	mgr.Close(port)

	// 5+10+20+40+80+160 ms: the seventh Accept would start after 315 ms.
	calls := len(ln.callTimes())
	require.GreaterOrEqual(t, calls, 2)
	require.LessOrEqual(t, calls, 8, "a failing listener is retried with growing pauses, not in a tight loop")
	require.Equal(t, 1, logs.count(slog.LevelWarn, "tcp accept failed"), "and the failure is logged once per interval")
}

func TestAcceptBackoffStartsOverAfterASuccess(t *testing.T) {
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: NewPool(40011, 40011), Logger: slog.New(&logCapture{})})
	visitorEnd, edgeEnd := net.Pipe()
	defer visitorEnd.Close()
	ln := newFakeListener(func(n int) (net.Conn, error, bool) {
		switch {
		case n <= 8: // pauses of 5, 10, 20, 40, 80, 160, 320 and 640 ms; the next would be 1 s
			return nil, errors.New("too many open files"), false
		case n == 9:
			return edgeEnd, nil, false
		case n == 10:
			return nil, errors.New("too many open files again"), false
		}
		return nil, nil, true
	})
	mgr.listen = func(int) (net.Listener, error) { return ln, nil }

	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	require.Eventually(t, func() bool { return len(ln.callTimes()) >= 11 }, 8*time.Second, 5*time.Millisecond)
	calls := ln.callTimes()
	require.GreaterOrEqual(t, calls[6].Sub(calls[5]), 140*time.Millisecond, "the sixth pause is 160 ms")
	// 5 ms against 1 s: the bound in between leaves room for a loaded machine.
	require.Less(t, calls[10].Sub(calls[9]), 600*time.Millisecond,
		"after a successful Accept the pause is 5 ms again, not 1 s")

	// The connection accepted between the errors is served.
	b, _ := acceptStream(t, sess)
	exchange(t, visitorEnd, b, "served")
}

// --- further cases from the attack list ------------------------------------------------

// A connection whose remote address cannot be parsed must not escape the
// per-source limit: all such connections share one budget.
func TestUnparsableRemoteAddressSharesOneSourceBudget(t *testing.T) {
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: NewPool(40012, 40012), MaxConnsPerTunnel: 100, MaxConnsPerIP: 2, MaxConns: 100})
	var visitorEnds []net.Conn
	ln := newFakeListener(func(n int) (net.Conn, error, bool) {
		if n > 3 {
			return nil, nil, true
		}
		v, e := net.Pipe() // RemoteAddr().String() is "pipe"
		visitorEnds = append(visitorEnds, v)
		return e, nil, false
	})
	mgr.listen = func(int) (net.Listener, error) { return ln, nil }
	sess := newScriptSession()
	defer sess.closeBackends()

	before := requestCount(t, "limit_ip")
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	require.Eventually(t, func() bool { return requestCount(t, "limit_ip") == before+1 }, 6*time.Second, 5*time.Millisecond,
		"the third connection without a parsable address is refused")
	require.Equal(t, 2, mgr.limiter.Total())
	require.EqualValues(t, 2, sess.opens.Load())
}

func TestDefaultConnLimitPerTunnelIs256(t *testing.T) {
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: NewPool(40013, 40013), MaxConnsPerIP: -1})
	var mu sync.Mutex
	var visitorEnds []net.Conn
	ln := newFakeListener(func(n int) (net.Conn, error, bool) {
		if n > 257 {
			return nil, nil, true
		}
		v, e := net.Pipe()
		mu.Lock()
		visitorEnds = append(visitorEnds, v)
		mu.Unlock()
		return e, nil, false
	})
	mgr.listen = func(int) (net.Listener, error) { return ln, nil }
	sess := newScriptSession()
	defer sess.closeBackends()

	before := requestCount(t, "limit_tunnel")
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	require.Eventually(t, func() bool { return requestCount(t, "limit_tunnel") == before+1 }, 6*time.Second, 5*time.Millisecond,
		"connection 257 to one tunnel is refused")
	require.Equal(t, 256, mgr.limiter.Total())
}
