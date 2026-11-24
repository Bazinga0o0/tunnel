package edgetcp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Further cases from the attack list: sources, sequences and error paths.

// addrConn is a connection that reports the given remote address.
type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

// connsFrom returns a listener that hands out one in-memory connection per
// source address and then blocks. The visitor ends go to the returned slice.
func connsFrom(sources []string) (*fakeListener, func() []net.Conn) {
	var mu sync.Mutex
	var visitorEnds []net.Conn
	ln := newFakeListener(func(n int) (net.Conn, error, bool) {
		if n > len(sources) {
			return nil, nil, true
		}
		v, e := net.Pipe()
		mu.Lock()
		visitorEnds = append(visitorEnds, v)
		mu.Unlock()
		return addrConn{Conn: e, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(sources[n-1]))}, nil, false
	})
	return ln, func() []net.Conn {
		mu.Lock()
		defer mu.Unlock()
		return append([]net.Conn(nil), visitorEnds...)
	}
}

func TestConnLimitPerSourceCountsAddressesNotPorts(t *testing.T) {
	sources := []string{
		"10.0.0.1:1000",
		"10.0.0.1:1001",
		"10.0.0.1:1002", // third connection of 10.0.0.1: refused
		"10.0.0.2:1000", // another address has its own budget
		"[::ffff:10.0.0.2]:1001",
		"[::ffff:10.0.0.2]:1002", // IPv4-mapped is the same address: refused
		"[2001:db8:1:2::1]:1000",
		"[2001:db8:1:2:ffff::2]:1000",
		"[2001:db8:1:2::3]:1000", // third connection of one /64: refused
		"[2001:db8:1:3::1]:1000", // another /64 has its own budget
	}
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: NewPool(40030, 40030), MaxConnsPerTunnel: 100, MaxConnsPerIP: 2, MaxConns: 100})
	ln, _ := connsFrom(sources)
	mgr.listen = func(int) (net.Listener, error) { return ln, nil }
	sess := newScriptSession()
	defer sess.closeBackends()

	before := requestCount(t, "limit_ip")
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	require.Eventually(t, func() bool { return requestCount(t, "limit_ip") == before+3 }, 6*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return sess.opens.Load() == 7 }, 6*time.Second, 5*time.Millisecond)
	require.Equal(t, 7, mgr.limiter.Total())

	// The stream headers name the visitors. Which two of the three
	// connections of one source got the slots is a race between their
	// handlers; what is fixed is how many each source got.
	perSource := map[string]int{}
	for i := 0; i < 7; i++ {
		_, hdr := acceptStream(t, sess)
		addr := netip.MustParseAddr(hdr.RemoteIP)
		key := addr.String()
		if addr.Is6() {
			key = netip.PrefixFrom(addr, 64).Masked().String()
		}
		perSource[key]++
	}
	require.Equal(t, map[string]int{
		"10.0.0.1":          2,
		"10.0.0.2":          2,
		"2001:db8:1:2::/64": 2,
		"2001:db8:1:3::/64": 1,
	}, perSource)
}

// A connection that Accept hands out after Close has finished gets no
// stream and is closed.
func TestConnectionAcceptedDuringCloseGetsNoStream(t *testing.T) {
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: NewPool(40031, 40031)})
	deliver := make(chan struct{})
	visitorEnd, edgeEnd := net.Pipe()
	defer visitorEnd.Close()
	ln := newFakeListener(func(n int) (net.Conn, error, bool) {
		if n == 1 {
			<-deliver // Accept returns only after Close has finished
			return edgeEnd, nil, false
		}
		return nil, nil, true
	})
	mgr.listen = func(int) (net.Listener, error) { return ln, nil }
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)

	mgr.Close(port)
	close(deliver)

	expectClosed(t, visitorEnd, 6*time.Second, "connection accepted after Close")
	require.Zero(t, sess.opens.Load(), "no stream is opened for a closed listener")
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// The idle timeout has to work when nobody waits on the visitor: the
// backend does not read, so the copy towards it is stuck in a stream write.
func TestIdleTimeoutCoversABackendThatDoesNotRead(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 400 * time.Millisecond})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := dial(t, port)
	acceptStream(t, sess) // reads the header and then nothing more
	start := time.Now()   // before the last byte moves
	_, err = v.Write([]byte("data the backend never reads"))
	require.NoError(t, err)

	expectClosed(t, v, 6*time.Second, "connection to a backend that does not read")
	require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// ... and when the backend never even reads the stream header.
func TestIdleTimeoutCoversAStreamHeaderThatIsNotTaken(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 400 * time.Millisecond})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	start := time.Now() // before the connection exists
	v := dial(t, port)
	expectClosed(t, v, 6*time.Second, "connection whose stream header is never read")
	require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
	require.EqualValues(t, 1, sess.opens.Load())
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// A connection that never carries a byte is idle from the start.
func TestConnectionWithoutAnyTrafficIsClosed(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 400 * time.Millisecond})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	start := time.Now() // before the connection exists
	v := dial(t, port)
	b, _ := acceptStream(t, sess)
	expectClosed(t, v, 6*time.Second, "connection without any traffic")
	require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
	expectClosed(t, b, 6*time.Second, "its stream")
}

// A visitor that resets the connection ends it for good, even without an
// idle timeout and with a backend that keeps its stream open.
func TestVisitorResetEndsTheConnectionWhileTheBackendStaysSilent(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: -1})
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
	require.Equal(t, 1, mgr.limiter.Total())

	require.NoError(t, v.SetLinger(0)) // Close now sends a reset instead of a clean end
	require.NoError(t, v.Close())

	require.Eventually(t, func() bool { return mgr.limiter.Visitors() == 0 }, 6*time.Second, 5*time.Millisecond,
		"the handler is still waiting for the backend")
	// The stream the backend keeps open holds its place in the total until it
	// is gone.
	require.Equal(t, 1, mgr.limiter.Total())
	require.NoError(t, st.Close())
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

func TestPanicInAcceptDoesNotEndTheProcess(t *testing.T) {
	logs := &logCapture{}
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: NewPool(40032, 40032), Logger: slog.New(logs)})
	ln := newFakeListener(func(n int) (net.Conn, error, bool) {
		if n == 1 {
			panic("boom in Accept")
		}
		return nil, nil, true
	})
	mgr.listen = func(int) (net.Listener, error) { return ln, nil }
	port, err := mgr.Open(context.Background(), 0, newScriptSession())
	require.NoError(t, err)
	defer mgr.Close(port)

	require.Eventually(t, func() bool { return logs.count(slog.LevelError, "panic recovered") == 1 },
		6*time.Second, 5*time.Millisecond)
}

// ... and when nobody waits on the stream: the visitor does not read, so
// the reply copy is stuck in a write to the visitor.
func TestIdleTimeoutCoversAVisitorThatDoesNotRead(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 400 * time.Millisecond})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	dial(t, port) // connects and never reads
	b, _ := acceptStream(t, sess)

	// The backend sends until it cannot get rid of more.
	start := time.Now()
	chunk := make([]byte, 64<<10)
	var writeErr error
	for i := 0; i < 2048 && writeErr == nil; i++ { // at most 128 MiB
		_ = b.SetWriteDeadline(time.Now().Add(8 * time.Second))
		_, writeErr = b.Write(chunk)
	}
	require.Error(t, writeErr, "the edge took 128 MiB for a visitor that reads nothing")
	var ne net.Error
	require.False(t, errors.As(writeErr, &ne) && ne.Timeout(), "the stream to a visitor that does not read was left open")
	require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}
