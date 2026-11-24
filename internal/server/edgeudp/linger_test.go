package edgeudp

import (
	"context"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// Streams the edge is done with. The stream of a flow counts against the
// total (edge.udp.max_flows) until it is gone from the tunnel session, not
// only until the flow has ended; what the client still sends meanwhile is
// read and thrown away.

// yamuxOpener opens streams of a yamux session.
type yamuxOpener struct{ s *yamux.Session }

func (o yamuxOpener) OpenStream() (protocol.Stream, error) {
	st, err := o.s.OpenStream()
	if err != nil {
		return nil, err
	}
	return st, nil
}

// lingerPair is a yamux session over an in-memory connection. The server side
// resets a stream closeTimeout after closing it (yamux's close timer).
func lingerPair(t *testing.T, closeTimeout time.Duration) (server, client *yamux.Session) {
	t.Helper()
	c1, c2 := net.Pipe()
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.EnableKeepAlive = false
	cfg.StreamCloseTimeout = closeTimeout
	server, err := yamux.Server(c1, cfg)
	require.NoError(t, err)
	ccfg := yamux.DefaultConfig()
	ccfg.LogOutput = io.Discard
	ccfg.EnableKeepAlive = false
	client, err = yamux.Client(c2, ccfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	return server, client
}

// acceptClient returns the tunnel client's end of the next flow after reading
// its header and first datagram, which must be want.
func acceptClient(t *testing.T, client *yamux.Session, want string) *yamux.Stream {
	t.Helper()
	ch := make(chan *yamux.Stream, 1)
	go func() {
		st, err := client.AcceptStream()
		if err != nil {
			ch <- nil
			return
		}
		if _, err := protocol.ReadStreamHeader(st); err != nil {
			ch <- nil
			return
		}
		got, err := protocol.ReadDatagram(st, nil)
		if err != nil || string(got) != want {
			ch <- nil
			return
		}
		ch <- st
	}()
	select {
	case st := <-ch:
		require.NotNil(t, st, "the flow did not reach the tunnel client")
		return st
	case <-time.After(6 * time.Second):
		t.Fatal("no flow reached the tunnel client")
		return nil
	}
}

// floodDatagrams writes datagrams to w as fast as it can until a write fails,
// counting the bytes.
func floodDatagrams(w io.Writer, written *atomic.Int64) {
	payload := make([]byte, 16<<10)
	for {
		if err := protocol.WriteDatagram(w, payload); err != nil {
			return
		}
		written.Add(int64(2 + len(payload)))
	}
}

// requireGoroutinesBackTo waits until no more than n goroutines run. It polls
// from the test's own goroutine: require.Eventually runs its condition in a
// goroutine of its own, which would count.
func requireGoroutinesBackTo(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for runtime.NumGoroutine() > n {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines are left: %d, before %d", runtime.NumGoroutine(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAFlowStreamTheClientKeepsOpenHoldsItsTotalSlotUntilItIsGone(t *testing.T) {
	for _, end := range []string{"the client closes its side", "the close timer fires", "the session ends"} {
		t.Run(end, func(t *testing.T) {
			closeTimeout := time.Minute
			if end == "the close timer fires" {
				closeTimeout = 3 * time.Second
			}
			server, client := lingerPair(t, closeTimeout)
			pool, ports := testPorts(t, 1)
			mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 300 * time.Millisecond,
				SweepInterval: 20 * time.Millisecond, MaxFlowsPerPort: 2, MaxFlowsPerIP: 1, MaxFlows: 10})
			port, err := mgr.Open(context.Background(), ports[0], yamuxOpener{server})
			require.NoError(t, err)
			defer mgr.Close(port)
			goroutines := runtime.NumGoroutine()

			// The visitor sends one datagram and nothing more, so its flow
			// idles out; the tunnel client keeps its side of the flow's
			// stream open and goes on writing as fast as it can.
			_, err = visitor(t, port).Write([]byte("hello"))
			require.NoError(t, err)
			st := acceptClient(t, client, "hello")
			var written atomic.Int64
			go floodDatagrams(st, &written)

			// The stream the address caused keeps counting against it: a flow
			// from another port of the same address is refused at the
			// per-address limit (1) while the stream lingers.
			require.Eventually(t, func() bool { return mgr.limiter.Visitors() == 0 }, 6*time.Second, 5*time.Millisecond)
			start := time.Now()
			refused := requestCount(t, "limit_ip")
			_, err = visitor(t, port).Write([]byte("second"))
			require.NoError(t, err)
			require.Eventually(t, func() bool { return requestCount(t, "limit_ip") == refused+1 }, 6*time.Second, 5*time.Millisecond,
				"a second flow of the address was not refused")

			// The stream of the first is not gone: it holds its place in the
			// total and stays in the session, where the per-user count counts
			// it. What the client sends on it is read and thrown away.
			require.Eventually(t, func() bool { return mgr.limiter.Visitors() == 0 && mgr.limiter.Total() == 1 },
				6*time.Second, 5*time.Millisecond)
			require.Equal(t, 1, server.NumStreams())
			from := written.Load()
			require.Eventually(t, func() bool { return written.Load() > from+8*protocol.StreamWindowBytes },
				6*time.Second, 5*time.Millisecond, "what the client sends piles up instead of being read")
			require.Equal(t, 1, mgr.limiter.Total())
			require.Less(t, time.Since(start), closeTimeout, "the checks above took longer than the close timer")

			switch end {
			case "the client closes its side":
				require.NoError(t, st.Close())
			case "the session ends":
				require.NoError(t, server.Close())
			}
			if end == "the session ends" { // a closed session keeps counting its streams
				require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 8*time.Second, 5*time.Millisecond,
					"the total slot is not given back when the stream is gone")
			} else {
				requireReleasedOnlyWhenGone(t, mgr.limiter.Total, server.NumStreams, 8*time.Second)
				// Gone: the address is admitted again.
				_, err = visitor(t, port).Write([]byte("again"))
				require.NoError(t, err)
				st3 := acceptClient(t, client, "again")
				require.NoError(t, st3.Close())
				require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
			}
			requireGoroutinesBackTo(t, goroutines)
		})
	}
}

// gatedConn is the tunnel client's end of the connection: while it is shut,
// the client does not read its connection.
type gatedConn struct {
	net.Conn
	mu   sync.Mutex
	open *sync.Cond
	shut bool
}

func (g *gatedConn) Read(p []byte) (int, error) {
	g.mu.Lock()
	for g.shut {
		g.open.Wait()
	}
	g.mu.Unlock()
	return g.Conn.Read(p)
}

func (g *gatedConn) set(shut bool) {
	g.mu.Lock()
	g.shut = shut
	g.mu.Unlock()
	g.open.Broadcast()
}

// Through the edge: the tunnel client keeps writing on
// the stream of a flow that has ended and stops reading its connection for
// many connection write timeouts. The stream stays counted in the total for
// as long as it is in the session.
func TestAClientThatStopsReadingKeepsItsFlowStreamCounted(t *testing.T) {
	const writeTimeout = 100 * time.Millisecond
	c1, c2 := net.Pipe()
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.EnableKeepAlive = false
	cfg.ConnectionWriteTimeout = writeTimeout
	server, err := yamux.Server(c1, cfg)
	require.NoError(t, err)
	gate := &gatedConn{Conn: c2}
	gate.open = sync.NewCond(&gate.mu)
	ccfg := yamux.DefaultConfig()
	ccfg.LogOutput = io.Discard
	ccfg.EnableKeepAlive = false
	client, err := yamux.Client(gate, ccfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		gate.set(false)
		_ = server.Close()
		_ = client.Close()
	})

	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 300 * time.Millisecond, SweepInterval: 20 * time.Millisecond})
	port, err := mgr.Open(context.Background(), ports[0], yamuxOpener{server})
	require.NoError(t, err)
	defer mgr.Close(port)

	_, err = visitor(t, port).Write([]byte("hello"))
	require.NoError(t, err)
	st := acceptClient(t, client, "hello")
	var written atomic.Int64
	go floodDatagrams(st, &written)
	require.Eventually(t, func() bool { return mgr.limiter.Visitors() == 0 && mgr.limiter.Total() == 1 },
		6*time.Second, 5*time.Millisecond)

	gate.set(true)
	for stop := time.Now().Add(15 * writeTimeout); time.Now().Before(stop); time.Sleep(5 * time.Millisecond) {
		require.Equal(t, 1, server.NumStreams())
		require.Equal(t, 1, mgr.limiter.Total(), "the stream left the total while it is still in the session")
	}
	gate.set(false)
	require.NoError(t, st.Close())
	requireReleasedOnlyWhenGone(t, mgr.limiter.Total, server.NumStreams, 8*time.Second)
}

// requireReleasedOnlyWhenGone watches the total and the session until the
// total is back to 0, and requires that the session no longer counts the
// stream then. yamux removes a stream a few microseconds after a forced close
// (the close timer) has woken its reader, so a count of 1 is looked at again
// after 50 ms before it counts as an early release. "Then" is approximate:
// the total is polled every millisecond, and an early release whose stream
// leaves the session within about 50 ms passes. The early releases this was
// written for kept the stream for a connection write timeout (100 ms to 1 s
// in these tests); the edgeguard test checks inside its release function.
func requireReleasedOnlyWhenGone(t *testing.T, total, streams func() int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for total() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the total slot did not come back")
		}
		time.Sleep(time.Millisecond)
	}
	if streams() != 0 {
		time.Sleep(50 * time.Millisecond)
		require.Zero(t, streams(), "the total slot came back while the session still counts the stream")
	}
}

// The race of the drain, through the real edge: the flow is
// evicted (its pump's write fails) while the client has half-closed the
// stream and does not read its connection, so the eviction's Close of the
// stream waits in yamux (for the window update that holds the control lock,
// then for its own write) before it removes the stream from the session;
// meanwhile the flow's reader ends on EOF. The stream must not be retired,
// and its place in the total must not come back, before that Close is over.
func TestAFlowStreamIsNotReleasedWhileItsCloseIsUnderWay(t *testing.T) {
	const writeTimeout = 300 * time.Millisecond
	c1, c2 := net.Pipe()
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.EnableKeepAlive = false
	cfg.ConnectionWriteTimeout = writeTimeout
	server, err := yamux.Server(c1, cfg)
	require.NoError(t, err)
	gate := &gatedConn{Conn: c2}
	gate.open = sync.NewCond(&gate.mu)
	ccfg := yamux.DefaultConfig()
	ccfg.LogOutput = io.Discard
	ccfg.EnableKeepAlive = false
	client, err := yamux.Client(gate, ccfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		gate.set(false)
		_ = server.Close()
		_ = client.Close()
	})

	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute, SweepInterval: time.Minute})
	port, err := mgr.Open(context.Background(), ports[0], yamuxOpener{server})
	require.NoError(t, err)
	defer mgr.Close(port)

	v := visitor(t, port)
	_, err = v.Write([]byte("hello"))
	require.NoError(t, err)
	st := acceptClient(t, client, "hello")
	require.Equal(t, 1, mgr.limiter.Total())

	gate.set(true)                     // the client stops reading its connection
	_, err = v.Write([]byte("second")) // the flow's pump cannot get this out
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	// Replies: the read that completes the third sends a window update (more
	// than half a window consumed) that cannot get out either; then the FIN.
	for _, n := range []int{65000, 65000, 1200} {
		require.NoError(t, protocol.WriteDatagram(st, make([]byte, n)))
	}
	require.NoError(t, st.Close())

	requireReleasedOnlyWhenGone(t, mgr.limiter.Total, server.NumStreams, 4*writeTimeout+4*time.Second)
}

// heldOpener opens a yamux stream and hands it to the edge only once proceed
// is closed.
type heldOpener struct {
	s       *yamux.Session
	proceed chan struct{}
}

func (o heldOpener) OpenStream() (protocol.Stream, error) {
	st, err := o.s.OpenStream()
	if err != nil {
		return nil, err
	}
	<-o.proceed
	return st, nil
}

// The wait in runFlow's retire path: the client
// has accepted the flow's stream and sent its FIN, then stops reading its
// connection. runFlow's write of the stream header waits and fails after the
// write timeout, while Manager.Close's Abort of the same stream is inside
// yamux's Close, waiting to get its FIN out before it removes the stream.
// runFlow retires the stream; a drain started then would read EOF at once
// and give the slot back with the stream still in the session.
func TestAFlowWhoseHeaderWriteFailsIsRetiredOnlyAfterTheOtherClose(t *testing.T) {
	const writeTimeout = time.Second // against the 200 ms below: Close reaches Abort well inside it
	c1, c2 := net.Pipe()
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.EnableKeepAlive = false
	cfg.ConnectionWriteTimeout = writeTimeout
	server, err := yamux.Server(c1, cfg)
	require.NoError(t, err)
	gate := &gatedConn{Conn: c2}
	gate.open = sync.NewCond(&gate.mu)
	ccfg := yamux.DefaultConfig()
	ccfg.LogOutput = io.Discard
	ccfg.EnableKeepAlive = false
	client, err := yamux.Client(gate, ccfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		gate.set(false)
		_ = server.Close()
		_ = client.Close()
	})

	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40032, 40032), IdleTimeout: time.Minute, SweepInterval: time.Minute})
	conn, feed := feedSocket(t)
	mgr.listen = func(int) (packetConn, error) { return conn, nil }
	proceed := make(chan struct{})
	port, err := mgr.Open(context.Background(), 0, heldOpener{s: server, proceed: proceed})
	require.NoError(t, err)

	feed <- datagram{[]byte("hello"), netip.MustParseAddrPort("192.0.2.1:4000")}
	accepted := make(chan *yamux.Stream, 1)
	go func() {
		st, _ := client.AcceptStream()
		accepted <- st
	}()
	var peer *yamux.Stream
	select {
	case peer = <-accepted:
		require.NotNil(t, peer)
	case <-time.After(6 * time.Second):
		t.Fatal("the flow's stream did not reach the client")
	}
	require.NoError(t, peer.Close()) // the client's FIN
	time.Sleep(50 * time.Millisecond)
	gate.set(true) // the client stops reading its connection
	close(proceed) // runFlow writes the header: that write waits
	time.Sleep(200 * time.Millisecond)
	closed := make(chan struct{})
	go func() { mgr.Close(port); close(closed) }() // its Abort waits in yamux's Close

	requireReleasedOnlyWhenGone(t, mgr.limiter.Total, server.NumStreams, 4*writeTimeout+4*time.Second)
	gate.set(false)
	<-closed
}

// An honest tunnel client closes its side when the flow's stream ends. The
// total slot is back at once: not after the close timer.
func TestAnHonestClientReleasesTheFlowSlotAtOnce(t *testing.T) {
	server, client := lingerPair(t, time.Minute)
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 300 * time.Millisecond, SweepInterval: 20 * time.Millisecond})
	port, err := mgr.Open(context.Background(), ports[0], yamuxOpener{server})
	require.NoError(t, err)
	defer mgr.Close(port)

	_, err = visitor(t, port).Write([]byte("hello"))
	require.NoError(t, err)
	st := acceptClient(t, client, "hello")
	// The flow idles out; the client closes its side when it sees the end
	// of the server's, as the tunnel client does.
	_ = st.SetReadDeadline(time.Now().Add(8 * time.Second))
	_, err = io.Copy(io.Discard, st)
	require.NoError(t, err)
	require.NoError(t, st.Close())
	start := time.Now()
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, time.Millisecond)
	require.Less(t, time.Since(start), time.Second)
	require.Zero(t, server.NumStreams())
}
