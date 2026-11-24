package edgehttp

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
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

// lingerTunnel is a tunnel whose streams are those of a yamux session.
type lingerTunnel struct {
	id string
	s  *yamux.Session
}

func (l *lingerTunnel) ID() string { return l.id }

func (l *lingerTunnel) OpenStream() (protocol.Stream, error) {
	st, err := l.s.OpenStream()
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

// acceptClient returns the tunnel client's end of the next stream, after its
// header, with a reader over it.
func acceptClient(t *testing.T, client *yamux.Session) (*yamux.Stream, *bufio.Reader) {
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
		return st, bufio.NewReader(st)
	case <-time.After(6 * time.Second):
		t.Fatal("no stream reached the tunnel client")
		return nil, nil
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
			f := newFixture(t, Options{MaxConnsPerTunnel: 2, MaxConnsPerIP: 1, TotalBudget: budget})
			require.NoError(t, f.reg.RegisterHTTP("abc", &lingerTunnel{id: "y", s: server}))
			goroutines := runtime.NumGoroutine()

			// The visitor sends a request and leaves; the tunnel client keeps
			// its side open and goes on writing as fast as it can.
			v := f.visit()
			v.send(get("/"))
			st, br := acceptClient(t, client)
			_, err := http.ReadRequest(br)
			require.NoError(t, err)
			var written atomic.Int64
			go flood(st, &written)
			start := time.Now()
			require.NoError(t, v.c.Close())

			// The stream the address caused keeps counting against it: a
			// second visitor from the same address is refused at the
			// per-address limit (1) while the stream lingers.
			require.Eventually(t, func() bool { return f.edge.limiter.Visitors() == 0 }, 6*time.Second, 5*time.Millisecond)
			refused := requestCount(t, "limit_ip")
			v2 := f.visit()
			v2.send(get("/"))
			res, _ := v2.recv()
			require.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
			require.Equal(t, refused+1, requestCount(t, "limit_ip"))
			require.NoError(t, v2.c.Close())

			// The stream of the first is not gone: it holds its place in the
			// total and stays in the session, where the per-user count counts
			// it. What the client sends on it is read and thrown away.
			require.Eventually(t, func() bool { return f.edge.limiter.Visitors() == 0 && f.edge.limiter.Total() == 1 },
				6*time.Second, 5*time.Millisecond)
			require.Equal(t, 1, budget.Used())
			require.Equal(t, 1, server.NumStreams())
			requirePaced(t, &written, start)
			require.Equal(t, 1, f.edge.limiter.Total())
			require.Less(t, time.Since(start), closeTimeout, "the checks above took longer than the close timer")

			switch end {
			case "the client closes its side":
				require.NoError(t, st.Close())
			case "the session ends":
				require.NoError(t, server.Close())
			}
			if end == "the session ends" { // a closed session keeps counting its streams
				require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 && budget.Used() == 0 },
					8*time.Second, 5*time.Millisecond, "the total slot is not given back when the stream is gone")
			} else {
				requireReleasedOnlyWhenGone(t, f.edge.limiter.Total, server.NumStreams, 8*time.Second)
				require.Zero(t, budget.Used())
				// Gone: the address is admitted again.
				v3 := f.visit()
				v3.send(get("/"))
				st3, br3 := acceptClient(t, client)
				_, err = http.ReadRequest(br3)
				require.NoError(t, err)
				_, err = st3.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
				require.NoError(t, err)
				v3.recvOK("ok")
				require.NoError(t, st3.Close())
				require.NoError(t, v3.c.Close())
				require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
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
	f := newFixture(t, Options{})
	require.NoError(t, f.reg.RegisterHTTP("abc", &lingerTunnel{id: "y", s: server}))

	v := f.visit()
	v.send(get("/"))
	st, br := acceptClient(t, client)
	_, err := http.ReadRequest(br)
	require.NoError(t, err)
	var written atomic.Int64
	go flood(st, &written)
	require.NoError(t, v.c.Close())
	require.Eventually(t, func() bool { return f.edge.limiter.Visitors() == 0 && f.edge.limiter.Total() == 1 },
		6*time.Second, 5*time.Millisecond)

	gate.set(true)
	for stop := time.Now().Add(15 * writeTimeout); time.Now().Before(stop); time.Sleep(5 * time.Millisecond) {
		require.Equal(t, 1, server.NumStreams())
		require.Equal(t, 1, f.edge.limiter.Total(), "the stream left the total while it is still in the session")
	}
	gate.set(false)
	require.NoError(t, st.Close())
	requireReleasedOnlyWhenGone(t, f.edge.limiter.Total, server.NumStreams, 8*time.Second)
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
	server, client := lingerPair(t, time.Minute)
	f := newFixture(t, Options{})
	require.NoError(t, f.reg.RegisterHTTP("abc", &lingerTunnel{id: "y", s: server}))

	v := f.visit()
	v.send(get("/"))
	st, br := acceptClient(t, client)
	_, err := http.ReadRequest(br)
	require.NoError(t, err)
	_, err = st.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	require.NoError(t, err)
	v.recvOK("ok")

	// The visitor leaves; the client closes its side when it sees the end of
	// the visitor's, as the tunnel client does.
	require.NoError(t, v.c.Close())
	_ = st.SetReadDeadline(time.Now().Add(8 * time.Second))
	_, err = io.Copy(io.Discard, br)
	require.NoError(t, err)
	require.NoError(t, st.Close())
	start := time.Now()
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, time.Millisecond)
	require.Less(t, time.Since(start), time.Second)
	require.Zero(t, server.NumStreams())
}

// The edge half-closes the stream when the visitor has finished sending, and
// when it refuses a follow-up request, and goes on delivering what the
// backend still owes. The drain must not start before that is through: an
// answer that comes late and is large arrives whole.
func TestALateLargeAnswerAfterAHalfCloseArrivesWhole(t *testing.T) {
	body := make([]byte, 4<<20)
	for i := range body {
		body[i] = 'a' + byte(i%26)
	}
	for _, tc := range []struct {
		name  string
		visit func(t *testing.T, v *visitor)
	}{
		{"the visitor half-closes", func(t *testing.T, v *visitor) {
			v.send(get("/"))
			require.NoError(t, v.c.CloseWrite())
		}},
		{"a refused follow-up request", func(t *testing.T, v *visitor) {
			v.send(get("/") + "GET / HTTP/1.1\r\nHost: other.localhost\r\n\r\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := lingerPair(t, time.Minute)
			f := newFixture(t, Options{})
			require.NoError(t, f.reg.RegisterHTTP("abc", &lingerTunnel{id: "y", s: server}))

			v := f.visit()
			tc.visit(t, v)
			st, br := acceptClient(t, client)
			go func() {
				defer st.Close()
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				if _, err := io.Copy(io.Discard, br); err != nil { // until the edge's half-close
					return
				}
				time.Sleep(100 * time.Millisecond)
				answer := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"), body...)
				for rest := answer; len(rest) > 0; rest = rest[min(len(rest), 4096):] {
					if _, err := st.Write(rest[:min(len(rest), 4096)]); err != nil {
						return
					}
				}
			}()

			_ = v.c.SetReadDeadline(time.Now().Add(20 * time.Second))
			res, err := http.ReadResponse(v.br, nil)
			require.NoError(t, err)
			require.Equal(t, 200, res.StatusCode)
			got, err := io.ReadAll(res.Body)
			require.NoError(t, err, "the answer after the half-close is cut")
			require.Equal(t, len(body), len(got))
			require.True(t, bytes.Equal(body, got), "the answer after the half-close is not the one the backend sent")
			require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
		})
	}
}
