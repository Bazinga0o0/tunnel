package edgeudp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
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

// acceptFlow returns the backend end of the next flow after reading its
// stream header. Reads and writes on it fail after five seconds so that a
// broken test ends instead of hanging.
func acceptFlow(t *testing.T, s *scriptSession) (protocol.Stream, *protocol.StreamHeader) {
	t.Helper()
	select {
	case st := <-s.streams:
		_ = st.(net.Conn).SetDeadline(time.Now().Add(8 * time.Second))
		hdr, err := protocol.ReadStreamHeader(st)
		require.NoError(t, err)
		return st, hdr
	case <-time.After(6 * time.Second):
		t.Fatal("no flow was opened towards the backend")
		return nil, nil
	}
}

// testPorts returns a pool of n free UDP ports and the ports themselves. No
// test binds a fixed port number: the system reserves port ranges that change
// from boot to boot. Tests pass the ports to Open as the preferred port.
func testPorts(t *testing.T, n int) (*Pool, []int) {
	t.Helper()
	low, high := testports.FreeUDPRange(t, n)
	ports := make([]int, 0, n)
	for p := low; p <= high; p++ {
		ports = append(ports, p)
	}
	return NewPool(low, high), ports
}

func visitor(t *testing.T, port int) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// requestCount reads tunneld_request_total{type="udp",status=status}.
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
			if labels["type"] == "udp" && labels["status"] == status {
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

// --- close and panics --------------------------------------------------------

// A datagram starts a flow, the listener is closed while the stream for
// that flow is still being opened, then the open completes. The flow must not
// be written into a map that Close has set to nil: that panic would end the
// process.
func TestCloseWhileFlowIsBeingCreatedDoesNotPanic(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute, SweepInterval: time.Minute})

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

	_, err = visitor(t, port).Write([]byte("first datagram"))
	require.NoError(t, err)

	select {
	case <-entered:
	case <-time.After(6 * time.Second):
		t.Fatal("the datagram did not start a flow")
	}

	mgr.Close(port) // listener goes away while OpenStream is in progress
	close(gate)     // ... and now the stream open completes

	// The stream that was opened for the dead listener must be closed again.
	select {
	case st := <-sess.streams:
		_ = st.(net.Conn).SetDeadline(time.Now().Add(8 * time.Second))
		n, err := io.Copy(io.Discard, st)
		var ne net.Error
		require.False(t, errors.As(err, &ne) && ne.Timeout(), "the freshly opened stream was left open")
		require.Zero(t, n, "the stream was put to use although its listener was closed")
	case <-time.After(6 * time.Second):
		t.Fatal("OpenStream did not complete")
	}
	require.Zero(t, mgr.limiter.Total(), "the flow of the closed listener still holds a slot")

	// The port is free again and a new listener on it works.
	sess2 := newScriptSession()
	port2, err := mgr.Open(context.Background(), ports[0], sess2)
	require.NoError(t, err)
	defer mgr.Close(port2)
	_, err = visitor(t, port2).Write([]byte("hello"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess2)
	got, err := protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
}

func TestPanicInFlowDoesNotEndTheProcess(t *testing.T) {
	logs := &logCapture{}
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, Logger: slog.New(logs)})

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

	_, err = visitor(t, port).Write([]byte("triggers the panic"))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return logs.count(slog.LevelError, "panic recovered") == 1 },
		6*time.Second, 10*time.Millisecond, "the panic is logged")

	// The port keeps working for the next flow.
	v := visitor(t, port)
	_, err = v.Write([]byte("ping"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	got, err := protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, "ping", string(got))
}

// --- limits ------------------------------------------------------------------

func TestDefaultsAndDisabledLimits(t *testing.T) {
	pool, _ := testPorts(t, 1)

	def := New(Options{BindHost: "127.0.0.1", Pool: pool})
	require.Equal(t, 256, def.opts.MaxFlowsPerPort)
	require.Equal(t, 64, def.opts.MaxFlowsPerIP)
	require.Equal(t, 768, def.opts.MaxFlows)
	require.Equal(t, 256, def.opts.ReplyCredit)
	require.Equal(t, 4096, def.opts.MaxReplyCredit)

	set := New(Options{BindHost: "127.0.0.1", Pool: pool, MaxFlowsPerPort: 7, MaxFlowsPerIP: 3, MaxFlows: 9, ReplyCredit: 2, MaxReplyCredit: 5})
	require.Equal(t, 7, set.opts.MaxFlowsPerPort)
	require.Equal(t, 3, set.opts.MaxFlowsPerIP)
	require.Equal(t, 9, set.opts.MaxFlows)
	require.Equal(t, 2, set.opts.ReplyCredit)
	require.Equal(t, 5, set.opts.MaxReplyCredit)

	// Negative disables; internally a disabled setting is zero.
	off := New(Options{BindHost: "127.0.0.1", Pool: pool, MaxFlowsPerPort: -1, MaxFlowsPerIP: -1, MaxFlows: -1, ReplyCredit: -1, MaxReplyCredit: -1})
	require.Zero(t, off.opts.MaxFlowsPerPort)
	require.Zero(t, off.opts.MaxFlowsPerIP)
	require.Zero(t, off.opts.MaxFlows)
	require.Zero(t, off.opts.ReplyCredit)
	require.Zero(t, off.opts.MaxReplyCredit)
}

// startFlows sends one datagram from n new visitors and waits until each has
// reached the backend.
func startFlows(t *testing.T, port int, sess *scriptSession, n int) []protocol.Stream {
	t.Helper()
	var streams []protocol.Stream
	for i := 0; i < n; i++ {
		_, err := visitor(t, port).Write([]byte("open"))
		require.NoError(t, err)
		st, _ := acceptFlow(t, sess)
		streams = append(streams, st)
	}
	return streams
}

func TestFlowLimitPerPort(t *testing.T) {
	pool, ports := testPorts(t, 2)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, MaxFlowsPerPort: 2, MaxFlowsPerIP: 100, MaxFlows: 100, IdleTimeout: time.Minute})

	sessA, sessB := newScriptSession(), newScriptSession()
	portA, err := mgr.Open(context.Background(), ports[0], sessA)
	require.NoError(t, err)
	defer mgr.Close(portA)
	portB, err := mgr.Open(context.Background(), ports[1], sessB)
	require.NoError(t, err)
	defer mgr.Close(portB)

	startFlows(t, portA, sessA, 2)
	before := requestCount(t, "limit_tunnel")

	// The third flow on port A is refused: dropped and counted, no stream.
	v := visitor(t, portA)
	for i := 0; i < 3; i++ {
		_, err = v.Write([]byte("over the limit"))
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool { return requestCount(t, "limit_tunnel") == before+3 },
		6*time.Second, 10*time.Millisecond, "each refused datagram is counted")
	require.EqualValues(t, 2, sessA.opens.Load(), "no stream is opened for a refused flow")

	// Port B has its own budget.
	startFlows(t, portB, sessB, 2)
}

func TestFlowLimitPerSourceIP(t *testing.T) {
	pool, ports := testPorts(t, 2)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, MaxFlowsPerPort: 100, MaxFlowsPerIP: 2, MaxFlows: 100, IdleTimeout: time.Minute})

	sessA, sessB := newScriptSession(), newScriptSession()
	portA, err := mgr.Open(context.Background(), ports[0], sessA)
	require.NoError(t, err)
	defer mgr.Close(portA)
	portB, err := mgr.Open(context.Background(), ports[1], sessB)
	require.NoError(t, err)
	defer mgr.Close(portB)

	startFlows(t, portA, sessA, 2)
	before := requestCount(t, "limit_ip")

	_, err = visitor(t, portA).Write([]byte("third flow from 127.0.0.1"))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return requestCount(t, "limit_ip") == before+1 },
		6*time.Second, 10*time.Millisecond)
	require.EqualValues(t, 2, sessA.opens.Load())

	// The limit is per port: the same source may open flows on port B.
	startFlows(t, portB, sessB, 2)
}

func TestFlowLimitTotal(t *testing.T) {
	pool, ports := testPorts(t, 2)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, MaxFlowsPerPort: 100, MaxFlowsPerIP: 100, MaxFlows: 3, IdleTimeout: time.Minute})

	sessA, sessB := newScriptSession(), newScriptSession()
	portA, err := mgr.Open(context.Background(), ports[0], sessA)
	require.NoError(t, err)
	defer mgr.Close(portA)
	portB, err := mgr.Open(context.Background(), ports[1], sessB)
	require.NoError(t, err)

	startFlows(t, portA, sessA, 2)
	startFlows(t, portB, sessB, 1)
	before := requestCount(t, "limit_total")

	_, err = visitor(t, portA).Write([]byte("fourth flow overall"))
	require.NoError(t, err)
	_, err = visitor(t, portB).Write([]byte("fifth flow overall"))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return requestCount(t, "limit_total") == before+2 },
		6*time.Second, 10*time.Millisecond)
	require.EqualValues(t, 2, sessA.opens.Load())
	require.EqualValues(t, 1, sessB.opens.Load())

	// Closing port B gives its flow back to the total.
	mgr.Close(portB)
	startFlows(t, portA, sessA, 1)
}

func TestFlowSlotIsReleasedWhenTheFlowExpires(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, MaxFlowsPerPort: 1, IdleTimeout: 500 * time.Millisecond, SweepInterval: 20 * time.Millisecond})

	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	startFlows(t, port, sess, 1)
	before := requestCount(t, "limit_tunnel")
	second := visitor(t, port)
	_, err = second.Write([]byte("refused"))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return requestCount(t, "limit_tunnel") == before+1 },
		6*time.Second, 10*time.Millisecond)

	// After the first flow has idled out its slot is free for the second visitor.
	require.Eventually(t, func() bool {
		_, err := second.Write([]byte("retry"))
		require.NoError(t, err)
		return sess.opens.Load() == 2
	}, 6*time.Second, 50*time.Millisecond, "the slot of an expired flow was not released")
}

func TestDisabledFlowLimits(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, MaxFlowsPerPort: -1, MaxFlowsPerIP: -1, MaxFlows: -1, IdleTimeout: time.Minute})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	// More flows from one source than the per-IP default of 64 allows.
	startFlows(t, port, sess, 70)
}

func TestDefaultFlowLimitPerSourceIPIs64(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	startFlows(t, port, sess, 64)
	before := requestCount(t, "limit_ip")
	_, err = visitor(t, port).Write([]byte("flow 65"))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return requestCount(t, "limit_ip") == before+1 },
		6*time.Second, 10*time.Millisecond)
	require.EqualValues(t, 64, sess.opens.Load())
}

// --- idle refresh ------------------------------------------------------------

func TestIdleTimerIsNotRefreshedByOutboundDatagrams(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 600 * time.Millisecond, SweepInterval: 20 * time.Millisecond})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := visitor(t, port)
	sent := time.Now()
	_, err = v.Write([]byte("one inbound datagram"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	_, err = protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	go func() { _, _ = io.Copy(io.Discard, v) }()

	// The backend keeps talking; the visitor stays silent.
	for time.Since(sent) < 6*time.Second {
		if err := protocol.WriteDatagram(st, []byte("chatter")); err != nil {
			require.GreaterOrEqual(t, time.Since(sent), 600*time.Millisecond, "the flow was closed before the idle timeout")
			return // the flow was closed although the backend was sending
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("the flow outlived the idle timeout because outbound datagrams refreshed it")
}

func TestIdleTimerIsRefreshedByInboundDatagrams(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 600 * time.Millisecond, SweepInterval: 20 * time.Millisecond})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := visitor(t, port)
	_, err = v.Write([]byte("0"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	_, err = protocol.ReadDatagram(st, nil)
	require.NoError(t, err)

	// One datagram every 100 ms for two seconds: more than three times the
	// idle timeout.
	for i := 1; i <= 20; i++ {
		time.Sleep(100 * time.Millisecond)
		_, err = v.Write([]byte{byte('0' + i%10)})
		require.NoError(t, err)
		got, err := protocol.ReadDatagram(st, nil)
		require.NoError(t, err, "datagram %d: the flow was closed although the visitor was active", i)
		require.Equal(t, []byte{byte('0' + i%10)}, got)
	}
	require.EqualValues(t, 1, sess.opens.Load(), "all datagrams used the same flow")
}

// --- reply credit ------------------------------------------------------------

// readAvailable reads the datagrams that arrive on the visitor socket. It
// waits patiently for the first want of them and then goes on until none
// arrives for 300 ms, so that a datagram too many is seen as well.
func readAvailable(t *testing.T, v *net.UDPConn, want int) [][]byte {
	t.Helper()
	var got [][]byte
	buf := make([]byte, 65536)
	for {
		wait := 300 * time.Millisecond
		if len(got) < want {
			wait = 6 * time.Second
		}
		_ = v.SetReadDeadline(time.Now().Add(wait))
		n, err := v.Read(buf)
		if err != nil {
			return got
		}
		got = append(got, append([]byte(nil), buf[:n]...))
	}
}

func TestReplyCredit(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, ReplyCredit: 3, MaxReplyCredit: 5, IdleTimeout: time.Minute})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := visitor(t, port)
	_, err = v.Write([]byte("in-1"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	_, err = protocol.ReadDatagram(st, nil)
	require.NoError(t, err)

	// One inbound datagram pays for three replies; the other seven are dropped.
	before := requestCount(t, "reply_limit")
	for i := 0; i < 10; i++ {
		require.NoError(t, protocol.WriteDatagram(st, []byte{'a', byte('0' + i)}))
	}
	got := readAvailable(t, v, 3)
	require.Equal(t, [][]byte{[]byte("a0"), []byte("a1"), []byte("a2")}, got)
	require.Eventually(t, func() bool { return requestCount(t, "reply_limit") == before+7 },
		6*time.Second, 10*time.Millisecond, "dropped replies are counted")

	// Three more inbound datagrams would pay for nine, but credit is capped at five.
	for i := 0; i < 3; i++ {
		_, err = v.Write([]byte("in"))
		require.NoError(t, err)
		_, err = protocol.ReadDatagram(st, nil)
		require.NoError(t, err)
	}
	for i := 0; i < 10; i++ {
		require.NoError(t, protocol.WriteDatagram(st, []byte{'b', byte('0' + i)}))
	}
	got = readAvailable(t, v, 5)
	require.Equal(t, [][]byte{[]byte("b0"), []byte("b1"), []byte("b2"), []byte("b3"), []byte("b4")}, got)

	// The flow itself survives running out of credit.
	_, err = v.Write([]byte("still there"))
	require.NoError(t, err)
	in, err := protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, "still there", string(in))
	require.EqualValues(t, 1, sess.opens.Load())
}

func TestReplyCreditDisabled(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, ReplyCredit: -1, IdleTimeout: time.Minute})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := visitor(t, port)
	_, err = v.Write([]byte("in"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	_, err = protocol.ReadDatagram(st, nil)
	require.NoError(t, err)

	const replies = 300 // more than the default credit of 256
	go func() {
		for i := 0; i < replies; i++ {
			if protocol.WriteDatagram(st, []byte("r")) != nil {
				return
			}
		}
	}()
	got := 0
	buf := make([]byte, 16)
	for got < replies {
		_ = v.SetReadDeadline(time.Now().Add(8 * time.Second))
		if _, err := v.Read(buf); err != nil {
			break
		}
		got++
	}
	require.Equal(t, replies, got)
}

func TestDefaultReplyCreditIs256(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := visitor(t, port)
	_, err = v.Write([]byte("in"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	_, err = protocol.ReadDatagram(st, nil)
	require.NoError(t, err)

	before := requestCount(t, "reply_limit")
	for i := 0; i < 300; i++ {
		require.NoError(t, protocol.WriteDatagram(st, []byte("r")))
	}
	// The manager has seen all 300 once the last 44 have been counted as dropped.
	require.Eventually(t, func() bool { return requestCount(t, "reply_limit") == before+44 },
		6*time.Second, 10*time.Millisecond, "256 replies pass, 44 are dropped")
}

// --- read loop, flow ids, buffers -------------------------------------------

func TestSlowStreamOpenDoesNotBlockOtherFlows(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute})

	gate := make(chan struct{})
	defer close(gate)
	sess := newScriptSession()
	sess.openHook = func(n int32) error {
		if n == 1 {
			<-gate // the first flow's stream never opens during this test
		}
		return nil
	}
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	_, err = visitor(t, port).Write([]byte("stuck flow"))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return sess.opens.Load() == 1 }, 6*time.Second, 5*time.Millisecond)

	// A second visitor is served while the first flow is still opening.
	v := visitor(t, port)
	_, err = v.Write([]byte("ping"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	got, err := protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, "ping", string(got))
	require.NoError(t, protocol.WriteDatagram(st, []byte("pong")))
	replies := readAvailable(t, v, 1)
	require.Equal(t, [][]byte{[]byte("pong")}, replies)
}

func TestDatagramsSentWhileTheStreamOpensAreDeliveredInOrder(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute, BufferSize: 8})

	gate := make(chan struct{})
	sess := newScriptSession()
	sess.openHook = func(int32) error { <-gate; return nil }
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := visitor(t, port)
	for i := 0; i < 5; i++ {
		_, err = v.Write([]byte{byte('0' + i)})
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}
	close(gate)

	st, _ := acceptFlow(t, sess)
	for i := 0; i < 5; i++ {
		got, err := protocol.ReadDatagram(st, nil)
		require.NoError(t, err)
		require.Equal(t, []byte{byte('0' + i)}, got)
	}
	require.EqualValues(t, 1, sess.opens.Load())
}

func TestFlowIDsArePerListener(t *testing.T) {
	pool, ports := testPorts(t, 2)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute})

	sessA, sessB := newScriptSession(), newScriptSession()
	portA, err := mgr.Open(context.Background(), ports[0], sessA)
	require.NoError(t, err)
	defer mgr.Close(portA)
	portB, err := mgr.Open(context.Background(), ports[1], sessB)
	require.NoError(t, err)
	defer mgr.Close(portB)

	var idsA, idsB []uint64
	for i := 0; i < 3; i++ {
		_, err = visitor(t, portA).Write([]byte("a"))
		require.NoError(t, err)
		_, hdr := acceptFlow(t, sessA)
		idsA = append(idsA, hdr.FlowID)
	}
	for i := 0; i < 2; i++ {
		_, err = visitor(t, portB).Write([]byte("b"))
		require.NoError(t, err)
		_, hdr := acceptFlow(t, sessB)
		idsB = append(idsB, hdr.FlowID)
	}
	require.Equal(t, []uint64{1, 2, 3}, idsA)
	require.Equal(t, []uint64{1, 2}, idsB, "a tunnel cannot read the activity of other tunnels from its flow ids")
}

func TestLargeRepliesOnConcurrentFlowsStayIntact(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	const flows, rounds, size = 4, 50, 60000
	type pair struct {
		v  *net.UDPConn
		st protocol.Stream
	}
	var pairs []pair
	for i := 0; i < flows; i++ {
		v := visitor(t, port)
		_, err = v.Write([]byte("open"))
		require.NoError(t, err)
		st, _ := acceptFlow(t, sess)
		_, err = protocol.ReadDatagram(st, nil)
		require.NoError(t, err)
		pairs = append(pairs, pair{v, st})
	}

	// Every backend sends payloads filled with its own byte while the other
	// flows do the same. A scratch buffer shared between flows would mix
	// them up. Each flow waits for its reply before it sends the next one so
	// that the test does not depend on the socket buffer size.
	var wg sync.WaitGroup
	errs := make(chan error, flows)
	for i, p := range pairs {
		fill := byte('A' + i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := bytes.Repeat([]byte{fill}, size)
			buf := make([]byte, 65536)
			for r := 0; r < rounds; r++ {
				if err := protocol.WriteDatagram(p.st, payload); err != nil {
					errs <- err
					return
				}
				_ = p.v.SetReadDeadline(time.Now().Add(8 * time.Second))
				n, err := p.v.Read(buf)
				if err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(payload, buf[:n]) {
					errs <- errors.New("payload of another flow or a damaged payload was delivered")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

// --- error logging -----------------------------------------------------------

func TestOpenStreamFailureIsLoggedAtMostOncePerInterval(t *testing.T) {
	logs := &logCapture{}
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, Logger: slog.New(logs), IdleTimeout: time.Minute})
	sess := newScriptSession()
	sess.openHook = func(int32) error { return errors.New("session is gone") }
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	const attempts = 30
	for i := 0; i < attempts; i++ {
		_, err = visitor(t, port).Write([]byte("x"))
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool { return sess.opens.Load() == attempts }, 6*time.Second, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, logs.count(slog.LevelWarn, "open stream failed"),
		"%d failed opens within one interval produce one warning", attempts)

	// A failed open leaves nothing behind: the next datagram tries again.
	v := visitor(t, port)
	_, err = v.Write([]byte("a"))
	require.NoError(t, err)
	_, err = v.Write([]byte("b"))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return sess.opens.Load() >= attempts+1 }, 6*time.Second, 10*time.Millisecond)
}

// fakePacketConn is a UDP socket whose reads follow a script.
type fakePacketConn struct {
	// script decides what read number n (from 1) returns. block makes the
	// read wait until the socket is closed.
	script func(n int) (data []byte, src netip.AddrPort, err error, block bool)
	sent   *atomic.Int32 // optional: counts the datagrams written to the socket

	mu     sync.Mutex
	calls  []time.Time
	once   sync.Once
	closed chan struct{}
}

func newFakePacketConn(script func(n int) ([]byte, netip.AddrPort, error, bool)) *fakePacketConn {
	return &fakePacketConn{script: script, closed: make(chan struct{})}
}

func (c *fakePacketConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	c.mu.Lock()
	c.calls = append(c.calls, time.Now())
	n := len(c.calls)
	c.mu.Unlock()

	data, src, err, block := c.script(n)
	if block || n > 100000 { // the cap keeps a loop without backoff from eating memory
		<-c.closed
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return copy(b, data), src, nil
}

func (c *fakePacketConn) WriteToUDPAddrPort(b []byte, _ netip.AddrPort) (int, error) {
	if c.sent != nil {
		c.sent.Add(1)
	}
	return len(b), nil
}

func (c *fakePacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakePacketConn) callTimes() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.calls...)
}

func TestReadErrorsBackOff(t *testing.T) {
	logs := &logCapture{}
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40000, 40000), Logger: slog.New(logs)})
	conn := newFakePacketConn(func(int) ([]byte, netip.AddrPort, error, bool) {
		return nil, netip.AddrPort{}, errors.New("socket is unhappy"), false
	})
	mgr.listen = func(int) (packetConn, error) { return conn, nil }

	port, err := mgr.Open(context.Background(), 0, newScriptSession())
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	mgr.Close(port)

	// 5+10+20+40+80+160 ms: the seventh read would start after 315 ms.
	calls := len(conn.callTimes())
	require.GreaterOrEqual(t, calls, 2)
	require.LessOrEqual(t, calls, 8, "a failing socket is retried with growing pauses, not in a tight loop")
	require.Equal(t, 1, logs.count(slog.LevelWarn, "udp read failed"), "and the failure is logged once per interval")
}

func TestReadBackoffStartsOverAfterASuccess(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40001, 40001), Logger: slog.New(&logCapture{})})
	src := netip.MustParseAddrPort("127.0.0.1:5353")
	conn := newFakePacketConn(func(n int) ([]byte, netip.AddrPort, error, bool) {
		switch {
		case n <= 8: // pauses of 5, 10, 20, 40, 80, 160, 320 and 640 ms; the next would be 1 s
			return nil, netip.AddrPort{}, errors.New("socket is unhappy"), false
		case n == 9:
			return []byte("a datagram"), src, nil, false
		case n == 10:
			return nil, netip.AddrPort{}, errors.New("socket is unhappy again"), false
		}
		return nil, netip.AddrPort{}, nil, true
	})
	mgr.listen = func(int) (packetConn, error) { return conn, nil }

	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	require.Eventually(t, func() bool { return len(conn.callTimes()) >= 11 }, 8*time.Second, 5*time.Millisecond)
	calls := conn.callTimes()
	require.GreaterOrEqual(t, calls[6].Sub(calls[5]), 140*time.Millisecond, "the sixth pause is 160 ms")
	// 5 ms against 1 s: the bound in between leaves room for a loaded machine.
	require.Less(t, calls[10].Sub(calls[9]), 600*time.Millisecond,
		"after a successful read the pause is 5 ms again, not 1 s")

	// The datagram between the errors was delivered.
	st, hdr := acceptFlow(t, sess)
	require.Equal(t, "127.0.0.1", hdr.RemoteIP)
	require.Equal(t, 5353, hdr.RemotePort)
	got, err := protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, "a datagram", string(got))
}
