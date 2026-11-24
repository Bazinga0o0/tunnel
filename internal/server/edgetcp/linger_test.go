package edgetcp

import (
	"bytes"
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
)

// Streams the edge is done with. A stream counts against the total
// (edge.max_conns) until it is gone from the tunnel session, not only until
// the visitor is gone; what the client still sends meanwhile is read and
// thrown away.

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

// acceptClient returns the tunnel client's end of the next stream after
// reading its header.
func acceptClient(t *testing.T, client *yamux.Session) *yamux.Stream {
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
		ch <- st
	}()
	select {
	case st := <-ch:
		require.NotNil(t, st, "the stream did not reach the tunnel client")
		return st
	case <-time.After(6 * time.Second):
		t.Fatal("no stream reached the tunnel client")
		return nil
	}
}

// flood writes to w as fast as it can until a write fails, counting the bytes.
func flood(w io.Writer, written *atomic.Int64) {
	chunk := make([]byte, 16<<10)
	for {
		n, err := w.Write(chunk)
		written.Add(int64(n))
		if err != nil {
			return
		}
	}
}

// testPace is the drain's default pace with its period scaled down from
// 30 s to 250 ms: the same bytes (two windows at full speed, then half a
// window per period), so every proportion of production holds, 120 times
// faster. A slot comes back within testPace.GoneWithin(window), about half a
// second, once the stream is gone.
var testPace = func() edgeguard.DrainPace {
	p := edgeguard.DefaultDrainPace
	p.Period = 250 * time.Millisecond
	return p
}()

// requirePaced asserts that the drain reads what the client keeps sending,
// at its pace: the client gets rid of more than the fast budget and a window
// (the drain reads), and never of more than the fast budget, a burst, the
// slow rate times the time since the visitor left, and three windows (what
// the edge read before it was done, the stream's buffer, what is in flight).
// The client is like an honest one whose local service keeps sending.
func requirePaced(t *testing.T, written *atomic.Int64, start time.Time) {
	t.Helper()
	low := int64(testPace.Fast + protocol.StreamWindowBytes)
	require.Eventually(t, func() bool { return written.Load() > low }, 6*time.Second, 5*time.Millisecond,
		"what the client sends is not read")
	rate := float64(testPace.Burst) / testPace.Period.Seconds()
	for i := 0; i < 20; i++ {
		time.Sleep(25 * time.Millisecond)
		high := float64(testPace.Fast+testPace.Burst+3*protocol.StreamWindowBytes) + rate*time.Since(start).Seconds()
		require.LessOrEqual(t, float64(written.Load()), high, "the drain reads faster than its pace")
	}
}

func TestAStreamTheClientKeepsOpenHoldsItsTotalSlotUntilItIsGone(t *testing.T) {
	defer edgeguard.SetDrainPaceForTesting(testPace)()
	for _, end := range []string{"the client closes its side", "the close timer fires", "the session ends"} {
		t.Run(end, func(t *testing.T) {
			closeTimeout := time.Minute
			if end == "the close timer fires" {
				closeTimeout = 3 * time.Second
			}
			server, client := lingerPair(t, closeTimeout)
			budget := edgeguard.NewBudget(10)
			pool, ports := testPorts(t, 1)
			mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool,
				MaxConnsPerTunnel: 2, MaxConnsPerIP: 1, TotalBudget: budget})
			port, err := mgr.Open(context.Background(), ports[0], yamuxOpener{server})
			require.NoError(t, err)
			defer mgr.Close(port)
			goroutines := runtime.NumGoroutine()

			// The visitor leaves; the tunnel client keeps its side open and
			// goes on writing as fast as it can.
			v := dial(t, port)
			st := acceptClient(t, client)
			var written atomic.Int64
			go flood(st, &written)
			start := time.Now()
			require.NoError(t, v.Close())

			// The stream the address caused keeps counting against it: a
			// second visitor from the same address is refused at the
			// per-address limit (1) while the stream lingers.
			require.Eventually(t, func() bool { return mgr.limiter.Visitors() == 0 }, 6*time.Second, 5*time.Millisecond)
			refused := requestCount(t, "limit_ip")
			expectClosed(t, dial(t, port), 6*time.Second, "a second connection of the address")
			require.Equal(t, refused+1, requestCount(t, "limit_ip"))

			// The stream of the first is not gone: it holds its place in the
			// total and stays in the session, where the per-user count counts
			// it. What the client sends on it is read, at the drain's pace, and
			// thrown away.
			require.Eventually(t, func() bool { return mgr.limiter.Visitors() == 0 && mgr.limiter.Total() == 1 },
				6*time.Second, 5*time.Millisecond)
			require.Equal(t, 1, budget.Used())
			require.Equal(t, 1, server.NumStreams())
			requirePaced(t, &written, start)
			require.Equal(t, 1, mgr.limiter.Total())
			require.Less(t, time.Since(start), closeTimeout, "the checks above took longer than the close timer")

			switch end {
			case "the client closes its side":
				require.NoError(t, st.Close())
			case "the session ends":
				require.NoError(t, server.Close())
			}
			if end == "the session ends" { // a closed session keeps counting its streams
				require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 && budget.Used() == 0 },
					8*time.Second, 5*time.Millisecond, "the total slot is not given back when the stream is gone")
			} else {
				requireReleasedOnlyWhenGone(t, mgr.limiter.Total, server.NumStreams, 8*time.Second)
				require.Zero(t, budget.Used())
				// Gone: the address is admitted again.
				v3 := dial(t, port)
				st3 := acceptClient(t, client)
				exchange(t, v3, st3, "admitted again")
				require.NoError(t, st3.Close())
				require.NoError(t, v3.Close())
				require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
			}
			requireGoroutinesBackTo(t, goroutines)
		})
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

// gatedLingerPair is lingerPair with a short connection write timeout on
// the server and a client whose reading of the connection can be stopped.
func gatedLingerPair(t *testing.T, writeTimeout time.Duration) (server, client *yamux.Session, gate *gatedConn) {
	t.Helper()
	c1, c2 := net.Pipe()
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.EnableKeepAlive = false
	cfg.ConnectionWriteTimeout = writeTimeout
	server, err := yamux.Server(c1, cfg)
	require.NoError(t, err)
	gate = &gatedConn{Conn: c2}
	gate.open = sync.NewCond(&gate.mu)
	ccfg := yamux.DefaultConfig()
	ccfg.LogOutput = io.Discard
	ccfg.EnableKeepAlive = false
	client, err = yamux.Client(gate, ccfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		gate.set(false)
		_ = server.Close()
		_ = client.Close()
	})
	return server, client, gate
}

// Through the edge: the tunnel client keeps writing on
// a stream the edge is done with and stops reading its connection for many
// connection write timeouts. The stream stays counted in the total for as
// long as it is in the session.
func TestAClientThatStopsReadingKeepsItsStreamCounted(t *testing.T) {
	defer edgeguard.SetDrainPaceForTesting(testPace)()
	const writeTimeout = 100 * time.Millisecond
	server, client, gate := gatedLingerPair(t, writeTimeout)
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})
	port, err := mgr.Open(context.Background(), ports[0], yamuxOpener{server})
	require.NoError(t, err)
	defer mgr.Close(port)

	v := dial(t, port)
	st := acceptClient(t, client)
	var written atomic.Int64
	go flood(st, &written)
	require.NoError(t, v.Close())
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
// written for kept the stream for a connection write timeout (100 to 300 ms
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

// An honest tunnel client closes its side as soon as it is done. The total
// slot is back at once: not after the close timer.
func TestAnHonestClientReleasesTheTotalSlotAtOnce(t *testing.T) {
	for _, first := range []string{"the backend ends first", "the visitor ends first"} {
		t.Run(first, func(t *testing.T) {
			server, client := lingerPair(t, time.Minute)
			pool, ports := testPorts(t, 1)
			mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})
			port, err := mgr.Open(context.Background(), ports[0], yamuxOpener{server})
			require.NoError(t, err)
			defer mgr.Close(port)

			v := dial(t, port)
			st := acceptClient(t, client)
			exchange(t, v, st, "hello")
			exchange(t, st, v, "hello back")
			if first == "the backend ends first" {
				require.NoError(t, st.Close())
				_ = v.SetReadDeadline(time.Now().Add(8 * time.Second))
				_, err = io.Copy(io.Discard, v)
				require.NoError(t, err)
				require.NoError(t, v.Close())
			} else {
				require.NoError(t, v.Close())
				// The client closes its side when it sees the end of the
				// visitor's, as the tunnel client does.
				_ = st.SetReadDeadline(time.Now().Add(8 * time.Second))
				_, err = io.Copy(io.Discard, st)
				require.NoError(t, err)
				require.NoError(t, st.Close())
			}
			start := time.Now()
			require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, time.Millisecond)
			require.Less(t, time.Since(start), time.Second)
			require.Zero(t, server.NumStreams())
		})
	}
}

// The edge half-closes the stream when the visitor has finished sending and
// goes on delivering the backend's answer. The drain must not start before
// that answer is through: an answer that comes late and is large arrives
// whole.
func TestALateLargeAnswerAfterTheVisitorsHalfCloseArrivesWhole(t *testing.T) {
	server, client := lingerPair(t, time.Minute)
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})
	port, err := mgr.Open(context.Background(), ports[0], yamuxOpener{server})
	require.NoError(t, err)
	defer mgr.Close(port)

	v := dial(t, port)
	st := acceptClient(t, client)
	_, err = v.Write([]byte("request"))
	require.NoError(t, err)
	require.NoError(t, v.CloseWrite())

	answer := make([]byte, 4<<20)
	for i := range answer {
		answer[i] = byte(i * 7)
	}
	go func() {
		got, err := io.ReadAll(st) // until the edge's half-close
		if err != nil || string(got) != "request" {
			_ = st.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
		for rest := answer; len(rest) > 0; rest = rest[min(len(rest), 4096):] {
			if _, err := st.Write(rest[:min(len(rest), 4096)]); err != nil {
				return
			}
		}
		_ = st.Close()
	}()

	_ = v.SetReadDeadline(time.Now().Add(20 * time.Second))
	got, err := io.ReadAll(v)
	require.NoError(t, err)
	require.Equal(t, len(answer), len(got), "the answer after the half-close is cut")
	require.True(t, bytes.Equal(answer, got), "the answer after the half-close is not the one the backend sent")
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}
