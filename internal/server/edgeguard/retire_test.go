package edgeguard

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// ---- Slot: the visitor's part and the total ----

// A slot's places (the total, the tunnel's, the source's) are held until
// the visitor and the stream opened for it are both gone: a stream that
// lingers after its visitor was caused by that visitor's address and keeps
// counting against it and against the tunnel. Visitors counts the visitors
// that are still there.
func TestASlotIsHeldUntilVisitorAndStreamAreGone(t *testing.T) {
	budget := NewBudget(5)
	l := NewLimiter(3, 2, 1)
	l.SetBudget(budget)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")

	s, err := l.Take("t", a)
	require.NoError(t, err)
	streamDone, ok := s.Hold()
	require.True(t, ok)
	require.Equal(t, 1, l.Total())
	require.Equal(t, 1, l.Visitors())
	require.Equal(t, 1, budget.Used())

	// The visitor is gone, its stream is not: every place stays taken.
	s.Release()
	require.Equal(t, 0, l.Visitors())
	require.Equal(t, 1, l.Total())
	require.Equal(t, 1, budget.Used())
	_, err = l.Take("t", a)
	require.ErrorIs(t, err, ErrLimitSource, "the lingering stream counts against its address")
	s2, err := l.Take("t", b)
	require.NoError(t, err, "another address is admitted")
	_, err = l.Take("t", netip.MustParseAddr("192.0.2.3"))
	require.ErrorIs(t, err, ErrLimitTunnel, "the lingering stream counts against its tunnel")
	s3, err := l.Take("u", a)
	require.NoError(t, err, "the address is admitted on another tunnel")
	_, err = l.Take("v", netip.MustParseAddr("192.0.2.4"))
	require.ErrorIs(t, err, ErrLimitTotal, "and against the total")

	// The stream is gone: its places come back.
	streamDone()
	require.Equal(t, 2, l.Total())
	require.Equal(t, 2, budget.Used())
	s5, err := l.Take("t", a)
	require.NoError(t, err, "the address is admitted again")
	streamDone() // more than once is harmless
	s.Release()  // so is this
	require.Equal(t, 3, l.Total())
	require.Equal(t, 3, l.Visitors())
	for _, x := range []*Slot{s2, s3, s5} {
		x.Release() // without a stream, Release gives back everything
	}
	require.Equal(t, 0, l.Total())
	require.Equal(t, 0, l.Visitors())
	require.Equal(t, 0, budget.Used())

	// A slot given back completely cannot be held again.
	s6, err := l.Take("t", a)
	require.NoError(t, err)
	s6.Release()
	done, ok := s6.Hold()
	require.False(t, ok)
	done()
	require.Equal(t, 0, l.Total())
	require.Equal(t, 0, budget.Used())

	// The stream may also be gone before the visitor.
	s7, err := l.Take("t", a)
	require.NoError(t, err)
	done, ok = s7.Hold()
	require.True(t, ok)
	done()
	require.Equal(t, 1, l.Total(), "the visitor still holds its places")
	_, err = l.Take("t", a)
	require.ErrorIs(t, err, ErrLimitSource)
	s7.Release()
	require.Equal(t, 0, l.Total())
	require.Equal(t, 0, budget.Used())
}

// With the defaults of the edges (64 per address and tunnel, 256 per
// tunnel): one address with 64 lingering streams on a tunnel is refused its
// next connection there, while another address is admitted there and the
// same address on another tunnel; once one of its streams is gone, the
// address is admitted again.
func TestOneAddressCanKeepAtMost64StreamsOfATunnelLingering(t *testing.T) {
	l := NewLimiter(1000, 256, 64)
	a := netip.MustParseAddr("198.51.100.7")
	var gone []func()
	for i := 0; i < 64; i++ {
		s, err := l.Take("tunnel", a)
		require.NoError(t, err)
		done, ok := s.Hold()
		require.True(t, ok)
		s.Release() // the visitor aborted; its stream lingers
		gone = append(gone, done)
	}
	require.Equal(t, 0, l.Visitors())
	require.Equal(t, 64, l.Total())
	_, err := l.Take("tunnel", a)
	require.ErrorIs(t, err, ErrLimitSource)
	other, err := l.Take("tunnel", netip.MustParseAddr("198.51.100.8"))
	require.NoError(t, err)
	other.Release()
	elsewhere, err := l.Take("another tunnel", a)
	require.NoError(t, err)
	elsewhere.Release()

	gone[0]() // the client closed one of the lingering streams
	again, err := l.Take("tunnel", a)
	require.NoError(t, err)
	again.Release()
	for _, done := range gone[1:] {
		done()
	}
	require.Equal(t, 0, l.Total())
}

func TestSlotsUnderConcurrencyAddUp(t *testing.T) {
	budget := NewBudget(0)
	l := NewLimiter(0, 0, 0)
	l.SetBudget(budget)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				s, err := l.Take("t", netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
				if err != nil {
					t.Error(err)
					return
				}
				done, _ := s.Hold()
				if j%2 == 0 {
					go s.Release()
					done()
				} else {
					go done()
					s.Release()
				}
			}
		}(i)
	}
	wg.Wait()
	require.Eventually(t, func() bool { return l.Total() == 0 && budget.Used() == 0 && l.Visitors() == 0 },
		6*time.Second, 5*time.Millisecond)
}

// ---- Retire: streams the edge is done with ----

// retirePair is a yamux session over an in-memory connection. The server
// side resets a stream closeTimeout after closing it.
func retirePair(t *testing.T, closeTimeout time.Duration) (server, client *yamux.Session) {
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

// floodingStream opens a stream from server to client whose client end
// writes as fast as it can until a write fails. It returns the server's end,
// the client's end and the count of bytes the client got rid of.
func floodingStream(t *testing.T, server, client *yamux.Session) (*yamux.Stream, *yamux.Stream, *atomic.Int64) {
	t.Helper()
	accepted := make(chan *yamux.Stream, 1)
	go func() {
		st, err := client.AcceptStream()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- st
	}()
	st, err := server.OpenStream()
	require.NoError(t, err)
	_, err = st.Write([]byte("x")) // the stream reaches the client with its first frame
	require.NoError(t, err)
	var peer *yamux.Stream
	select {
	case peer = <-accepted:
		require.NotNil(t, peer)
	case <-time.After(6 * time.Second):
		t.Fatal("the client did not accept the stream")
	}
	written := &atomic.Int64{}
	go func() {
		chunk := make([]byte, 16<<10)
		for {
			n, err := peer.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	return st, peer, written
}

// requireDraining asserts that the client keeps getting rid of its bytes: far
// more than the stream's window arrives while nobody but the drain reads.
func requireDraining(t *testing.T, written *atomic.Int64) {
	t.Helper()
	from := written.Load()
	require.Eventually(t, func() bool { return written.Load() > from+8*protocol.StreamWindowBytes },
		6*time.Second, 5*time.Millisecond, "what the client sends piles up instead of being read")
}

func TestRetireDrainsAStreamUntilItIsGone(t *testing.T) {
	for _, end := range []string{"the client closes its side", "the close timer fires", "the session ends"} {
		t.Run(end, func(t *testing.T) {
			closeTimeout := time.Minute
			if end == "the close timer fires" {
				closeTimeout = 2 * time.Second
			}
			server, client := retirePair(t, closeTimeout)
			st, peer, written := floodingStream(t, server, client)
			before := Draining()

			var released atomic.Int32
			start := time.Now()
			Retire(st, func() { released.Add(1) }, slog.Default())
			requireDraining(t, written)
			require.Zero(t, released.Load(), "released while the stream is still there")
			require.Equal(t, before+1, Draining())
			require.Equal(t, 1, server.NumStreams(), "the stream is still in the session")
			require.Less(t, time.Since(start), closeTimeout)

			switch end {
			case "the client closes its side":
				require.NoError(t, peer.Close())
			case "the session ends":
				require.NoError(t, server.Close())
			}
			require.Eventually(t, func() bool { return released.Load() == 1 }, 8*time.Second, 5*time.Millisecond)
			require.Eventually(t, func() bool { return Draining() == before }, 6*time.Second, 5*time.Millisecond,
				"the drain goroutine is left")
			if end != "the session ends" { // a closed session keeps its map; it is garbage as a whole
				require.Zero(t, server.NumStreams())
			}
		})
	}
}

// gatedConn is the tunnel client's end of the connection: while it is shut,
// the client does not read its connection, as a client that stops reading
// its TCP connection. The server's writes on it then block.
type gatedConn struct {
	net.Conn
	mu   sync.Mutex
	open *sync.Cond
	shut bool
}

func newGatedConn(c net.Conn) *gatedConn {
	g := &gatedConn{Conn: c}
	g.open = sync.NewCond(&g.mu)
	return g
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

// gatedRetirePair is retirePair with a short connection write timeout on
// the server and a client whose reading of the connection can be stopped.
func gatedRetirePair(t *testing.T, writeTimeout, closeTimeout time.Duration) (server, client *yamux.Session, gate *gatedConn) {
	t.Helper()
	c1, c2 := net.Pipe()
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.EnableKeepAlive = false
	cfg.ConnectionWriteTimeout = writeTimeout
	cfg.StreamCloseTimeout = closeTimeout
	server, err := yamux.Server(c1, cfg)
	require.NoError(t, err)
	gate = newGatedConn(c2)
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

// A client that stops reading its connection makes
// the window update of a drain read wait for the connection write timeout
// and fail; yamux returns that error together with the bytes the read got.
// That must not end the drain: the stream is still in the session, and
// without the drain its buffer would fill to the window with nobody
// reading and no slot counting it. The drain ends only when the stream is
// gone.
func TestAClientThatStopsReadingCannotEndTheDrain(t *testing.T) {
	const writeTimeout = 100 * time.Millisecond
	for _, end := range []string{"the client closes its side", "the close timer fires", "the session ends"} {
		t.Run(end, func(t *testing.T) {
			closeTimeout := time.Minute
			if end == "the close timer fires" {
				closeTimeout = 4 * time.Second
			}
			server, client, gate := gatedRetirePair(t, writeTimeout, closeTimeout)
			st, peer, written := floodingStream(t, server, client)
			before := Draining()
			var released, countedAtRelease atomic.Int32
			Retire(st, func() {
				// At the moment of release the session no longer counts the
				// stream (after a forced close yamux removes it a few
				// microseconds after waking the reader; a closed session
				// keeps its map).
				n := server.NumStreams()
				if n != 0 && !server.IsClosed() {
					time.Sleep(50 * time.Millisecond)
					n = server.NumStreams()
				}
				if server.IsClosed() {
					n = 0
				}
				countedAtRelease.Store(int32(n))
				released.Add(1)
			}, slog.Default())
			requireDraining(t, written)

			// The client stops reading its connection for many write
			// timeouts while it goes on writing on the stream.
			gate.set(true)
			for stop := time.Now().Add(15 * writeTimeout); time.Now().Before(stop); time.Sleep(5 * time.Millisecond) {
				require.Zero(t, released.Load(), "the drain ended while the stream is still in the session")
				require.Equal(t, 1, server.NumStreams())
			}
			// Once it reads again, what it sends is read again: the buffer
			// does not stay full.
			gate.set(false)
			requireDraining(t, written)
			require.Zero(t, released.Load())
			require.Equal(t, before+1, Draining())

			switch end {
			case "the client closes its side":
				require.NoError(t, peer.Close())
			case "the session ends":
				require.NoError(t, server.Close())
			}
			require.Eventually(t, func() bool { return released.Load() == 1 }, 8*time.Second, 5*time.Millisecond)
			require.Zero(t, countedAtRelease.Load(), "released while the session still counts the stream")
			require.Eventually(t, func() bool { return Draining() == before }, 6*time.Second, 5*time.Millisecond)
		})
	}
}

// A race at the level of the drain: a
// Close of another goroutine has set the stream's state to closed but still
// waits in yamux (for the control lock that a blocked window update holds,
// then for its own write) before it removes the stream from the session. A
// drain started meanwhile reads EOF at once: that is why the stream may be
// retired only after every closing call has returned. This test pins the
// yamux behaviour the contract of Retire rests on.
func TestEOFComesBeforeAnUnfinishedCloseRemovesTheStream(t *testing.T) {
	const writeTimeout = 200 * time.Millisecond
	server, client, gate := gatedRetirePair(t, writeTimeout, time.Minute)
	accepted := make(chan *yamux.Stream, 1)
	go func() {
		st, _ := client.AcceptStream()
		accepted <- st
	}()
	st, err := server.OpenStream()
	require.NoError(t, err)
	_, err = st.Write([]byte("x"))
	require.NoError(t, err)
	peer := <-accepted
	require.NotNil(t, peer)

	gate.set(true)
	// More than half a window: the read below sends a window update that
	// cannot get out and holds the stream's control lock while it waits.
	_, err = peer.Write(make([]byte, protocol.StreamWindowBytes/2+1024))
	require.NoError(t, err)
	require.NoError(t, peer.Close()) // FIN: the server's side is half-closed by the peer
	time.Sleep(50 * time.Millisecond)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		// One read takes everything buffered, more than half a window, and
		// then blocks in its window update.
		_, _ = st.Read(make([]byte, protocol.StreamWindowBytes))
	}()
	time.Sleep(50 * time.Millisecond) // the read is in its blocked window update
	closed := make(chan struct{})
	go func() { _ = st.Close(); close(closed) }()
	time.Sleep(20 * time.Millisecond)

	n, err := st.Read(make([]byte, 1))
	require.Zero(t, n)
	require.ErrorIs(t, err, io.EOF, "the state is closed")
	require.Equal(t, 1, server.NumStreams(), "the unfinished Close has not removed the stream yet")
	gate.set(false)
	<-closed
	<-readDone
	require.Eventually(t, func() bool { return server.NumStreams() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// An Abort that lands after Retire (another goroutine of the edge that was
// still on its way out) does not end the drain: a deadline is not the end of
// the stream.
func TestRetireOutlastsALateAbort(t *testing.T) {
	server, client := retirePair(t, time.Minute)
	st, peer, written := floodingStream(t, server, client)
	var released atomic.Int32
	Retire(st, func() { released.Add(1) }, slog.Default())
	requireDraining(t, written)
	Abort(st)
	requireDraining(t, written)
	require.Zero(t, released.Load())
	require.NoError(t, peer.Close())
	require.Eventually(t, func() bool { return released.Load() == 1 }, 6*time.Second, 5*time.Millisecond)
}

// A stream that is gone already, or whose Close ends it at once, is let go at
// once.
func TestRetireLetsGoOfAStreamThatIsGoneAtOnce(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	released := make(chan struct{})
	Retire(b, func() { close(released) }, slog.Default())
	select {
	case <-released:
	case <-time.After(6 * time.Second):
		t.Fatal("the drain of a closed pipe did not end")
	}

	// With yamux: the client has closed its side before the edge is done.
	server, client := retirePair(t, time.Minute)
	accepted := make(chan *yamux.Stream, 1)
	go func() {
		st, _ := client.AcceptStream()
		accepted <- st
	}()
	st, err := server.OpenStream()
	require.NoError(t, err)
	_, err = st.Write([]byte("x"))
	require.NoError(t, err)
	peer := <-accepted
	require.NotNil(t, peer)
	_, err = peer.Write([]byte("answer"))
	require.NoError(t, err)
	require.NoError(t, peer.Close())
	got, err := io.ReadAll(st)
	require.NoError(t, err)
	require.Equal(t, "answer", string(got))

	released = make(chan struct{})
	start := time.Now()
	Retire(st, func() { close(released) }, nil)
	select {
	case <-released:
	case <-time.After(6 * time.Second):
		t.Fatal("the drain of a stream both sides closed did not end")
	}
	require.Less(t, time.Since(start), time.Second)
	require.Zero(t, server.NumStreams())

	Retire(&panicReader{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil))) // nil release is fine
	require.Eventually(t, func() bool { return Draining() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// shrinkCounter is a stream that hands out full reads and counts the calls
// of Shrink that come after a read.
type shrinkCounter struct {
	net.Conn
	limit   int           // reads before EOF; at least 5
	delay   time.Duration // each read takes this long
	mu      sync.Mutex
	reads   int
	shrinks int
	lastWas string
}

func (s *shrinkCounter) Read(p []byte) (int, error) {
	time.Sleep(s.delay)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reads == max(s.limit, 5) {
		return 0, io.EOF
	}
	s.reads++
	s.lastWas = "read"
	return len(p), nil // a full buffer: the stream may have been read empty all the same
}

func (s *shrinkCounter) Shrink() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastWas == "read" {
		s.shrinks++
	}
	s.lastWas = "shrink"
}
func (s *shrinkCounter) Close() error                { return nil }
func (s *shrinkCounter) SetDeadline(time.Time) error { return nil }

// A client that writes in pieces of exactly the drain's buffer empties the
// stream's receive buffer with reads that fill the drain's buffer. The drain
// lets the stream give back its memory after every read, not only after a
// short one.
func TestRetireLetsTheStreamGiveBackItsBufferAfterEveryRead(t *testing.T) {
	s := &shrinkCounter{}
	released := make(chan struct{})
	Retire(s, func() { close(released) }, nil)
	select {
	case <-released:
	case <-time.After(6 * time.Second):
		t.Fatal("the drain did not end")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Equal(t, 5, s.reads)
	require.GreaterOrEqual(t, s.shrinks, 5, "Shrink was not asked after a full read")
}

// The paced drain (HTTP and TCP) asks the stream to give back its buffer at
// most about once a second, and once at the end: once the buffer is gone,
// yamux allocates a new one for every frame, so a client sending tiny frames
// into an emptied stream would make the server allocate for each of them.
// Between two shrinks the buffer holds at most what the window lets in (with
// yamux's growth up to about twice the window), which the 704 KiB of a TCP or
// HTTP slot counts. The full-speed drain of UDP flows keeps shrinking after
// every read (TestRetireLetsTheStreamGiveBackItsBufferAfterEveryRead): a flow
// is counted at 96 KiB, less than a buffer can hold between two shrinks.
//
// The drain asks only when a read returns: a buffer that is emptied just
// after a shrink stays allocated (inside the slot) while the client is
// silent.
func TestAPacedDrainShrinksAtMostOnceASecond(t *testing.T) {
	// 300 reads at once: one shrink, at the end.
	s := &shrinkCounter{limit: 300}
	released := make(chan struct{})
	start := time.Now()
	RetirePaced(s, func() { close(released) }, nil)
	select {
	case <-released:
	case <-time.After(6 * time.Second):
		t.Fatal("the drain did not end")
	}
	s.mu.Lock()
	require.Equal(t, 300, s.reads)
	require.GreaterOrEqual(t, s.shrinks, 1, "the buffer is given back at the end")
	require.LessOrEqual(t, s.shrinks, 1+int(time.Since(start)/time.Second)+1, "shrinks: %d", s.shrinks)
	s.mu.Unlock()

	// A drain whose reads go on for about 2.5 s: shrinks before its end too,
	// about once a second.
	s = &shrinkCounter{limit: 250, delay: 10 * time.Millisecond}
	released = make(chan struct{})
	start = time.Now()
	RetirePaced(s, func() { close(released) }, nil)
	select {
	case <-released:
	case <-time.After(20 * time.Second):
		t.Fatal("the drain did not end")
	}
	took := time.Since(start)
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Equal(t, 250, s.reads)
	require.GreaterOrEqual(t, took, 2*time.Second)
	require.GreaterOrEqual(t, s.shrinks, max(2, int(took/time.Second)), "a long drain did not shrink before its end (took %v)", took)
	require.LessOrEqual(t, s.shrinks, 1+int(took/time.Second)+1, "shrinks: %d", s.shrinks)
}

// recordingHandler is a slog.Handler that keeps the messages.
type recordingHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler            { return h }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	return nil
}

func (h *recordingHandler) count(msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, m := range h.msgs {
		if m == msg {
			n++
		}
	}
	return n
}

// panicReader is a stream whose Read panics.
type panicReader struct{ net.Conn }

func (p *panicReader) Read([]byte) (int, error)    { panic("boom in drain") }
func (p *panicReader) Close() error                { return nil }
func (p *panicReader) SetDeadline(time.Time) error { return nil }

// A panic in the drain costs the drain, not the process, and the slot is
// given back.
func TestRetireRecoversAPanicOfTheStream(t *testing.T) {
	logs := &recordingHandler{}
	released := make(chan struct{})
	before := Draining()
	Retire(&panicReader{}, func() { close(released) }, slog.New(logs))
	select {
	case <-released:
	case <-time.After(6 * time.Second):
		t.Fatal("the slot of a drain that panicked was not given back")
	}
	require.Eventually(t, func() bool { return Draining() == before }, 6*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return logs.count("panic recovered") == 1 }, 6*time.Second, 5*time.Millisecond)
}
