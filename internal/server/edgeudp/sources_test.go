package edgeudp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// Tests that need datagrams from other addresses than 127.0.0.1 or exact
// control over the socket. They feed the manager through a scripted socket.

// feed returns a socket that delivers one datagram from each source and then
// blocks, and counts the datagrams the manager sends.
func feed(sources []netip.AddrPort, sent *atomic.Int32) *fakePacketConn {
	c := newFakePacketConn(func(n int) ([]byte, netip.AddrPort, error, bool) {
		if n > len(sources) {
			return nil, netip.AddrPort{}, nil, true
		}
		return []byte("hi"), sources[n-1], nil, false
	})
	c.sent = sent
	return c
}

func TestFlowLimitPerSourceCountsAddressesNotPorts(t *testing.T) {
	sources := []netip.AddrPort{
		netip.MustParseAddrPort("10.0.0.1:1000"),
		netip.MustParseAddrPort("10.0.0.1:1001"),
		netip.MustParseAddrPort("10.0.0.1:1002"), // third flow of 10.0.0.1: refused
		netip.MustParseAddrPort("10.0.0.2:1000"), // another address has its own budget
		netip.MustParseAddrPort("[::ffff:10.0.0.2]:1001"),
		netip.MustParseAddrPort("[::ffff:10.0.0.2]:1002"), // IPv4-mapped is the same address: refused
		netip.MustParseAddrPort("[2001:db8:1:2::1]:1000"),
		netip.MustParseAddrPort("[2001:db8:1:2:ffff::2]:1000"),
		netip.MustParseAddrPort("[2001:db8:1:2::3]:1000"), // third flow of one /64: refused
		netip.MustParseAddrPort("[2001:db8:1:3::1]:1000"), // another /64 has its own budget
	}
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40020, 40020), MaxFlowsPerPort: 100, MaxFlowsPerIP: 2, MaxFlows: 100, IdleTimeout: time.Minute})
	mgr.listen = func(int) (packetConn, error) { return feed(sources, nil), nil }
	sess := newScriptSession()

	before := requestCount(t, "limit_ip")
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	require.Eventually(t, func() bool { return requestCount(t, "limit_ip") == before+3 }, 6*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return sess.opens.Load() == 7 }, 6*time.Second, 5*time.Millisecond)
	require.Equal(t, 7, mgr.limiter.Total())

	// The stream headers name the visitors, IPv4-mapped addresses as IPv4.
	var got []string
	for i := 0; i < 7; i++ {
		_, hdr := acceptFlow(t, sess)
		got = append(got, fmt.Sprintf("%s|%d", hdr.RemoteIP, hdr.RemotePort))
	}
	sort.Strings(got)
	require.Equal(t, []string{
		"10.0.0.1|1000", "10.0.0.1|1001", "10.0.0.2|1000", "10.0.0.2|1001",
		"2001:db8:1:2::1|1000", "2001:db8:1:2:ffff::2|1000", "2001:db8:1:3::1|1000",
	}, got)
}

// The other half of closing: a datagram that the read loop had already taken
// from the socket when Close ran must not start a flow on the closed
// listener.
func TestDatagramReadBeforeCloseIsDroppedAfterClose(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40021, 40021), IdleTimeout: time.Minute})
	deliver := make(chan struct{})
	conn := newFakePacketConn(func(n int) ([]byte, netip.AddrPort, error, bool) {
		if n == 1 {
			<-deliver // the read returns only after Close has finished
			return []byte("late"), netip.MustParseAddrPort("10.0.0.1:1000"), nil, false
		}
		return nil, netip.AddrPort{}, nil, true
	})
	mgr.listen = func(int) (packetConn, error) { return conn, nil }
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)

	mgr.mu.Lock()
	al := mgr.byPort[port]
	mgr.mu.Unlock()
	require.NotNil(t, al)

	mgr.Close(port)
	close(deliver)
	require.Eventually(t, func() bool { return len(conn.callTimes()) == 2 }, 6*time.Second, 5*time.Millisecond,
		"the late datagram has been handled")
	time.Sleep(20 * time.Millisecond)

	require.Zero(t, sess.opens.Load(), "no stream is opened for a closed listener")
	require.Zero(t, mgr.limiter.Total())
	al.mu.Lock()
	defer al.mu.Unlock()
	require.True(t, al.closed)
	require.NotNil(t, al.flows, "Close must leave the flow map in place")
	require.Empty(t, al.flows)
}

// A flow holds a scratch buffer only while a reply is in transit. With a
// buffer per flow these 200 idle flows would pin 200 * 64 KiB = 12.8 MiB.
func TestIdleFlowsHoldNoScratchBuffer(t *testing.T) {
	const flows = 200
	var sources []netip.AddrPort
	for i := 0; i < flows; i++ {
		sources = append(sources, netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), uint16(2000+i)))
	}
	var sent atomic.Int32
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40022, 40022), MaxFlowsPerIP: -1, IdleTimeout: time.Minute})
	mgr.listen = func(int) (packetConn, error) { return feed(sources, &sent), nil }
	sess := newScriptSession()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	// Every backend answers once, so every flow has used a buffer, and then
	// stays connected and silent.
	var streams []protocol.Stream
	for i := 0; i < flows; i++ {
		st, _ := acceptFlow(t, sess)
		_, err := protocol.ReadDatagram(st, nil)
		require.NoError(t, err)
		require.NoError(t, protocol.WriteDatagram(st, []byte("reply")))
		streams = append(streams, st)
	}
	require.Eventually(t, func() bool { return sent.Load() == flows }, 6*time.Second, 5*time.Millisecond)

	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	held := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	require.Less(t, held, int64(4<<20), "%d idle flows hold %d bytes of heap", flows, held)
	runtime.KeepAlive(streams)
}

// closePanicStream panics when it is closed.
type closePanicStream struct {
	net.Conn // the stream; embedding the conn keeps its deadline methods
}

func (closePanicStream) Close() error { panic("boom in stream close") }

func TestPanicWhileEvictingAFlowDoesNotStopTheSweeper(t *testing.T) {
	logs := &logCapture{}
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, Logger: slog.New(logs), IdleTimeout: 500 * time.Millisecond, SweepInterval: 20 * time.Millisecond})
	sess := newScriptSession()
	sess.wrap = func(s protocol.Stream) protocol.Stream {
		if sess.opens.Load() == 1 {
			return closePanicStream{s.(net.Conn)}
		}
		return s
	}
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer func() {
		defer func() { _ = recover() }() // Close runs in the test goroutine and meets the same stream
		mgr.Close(port)
	}()

	// The first flow idles out; closing its stream panics inside the sweeper.
	_, err = visitor(t, port).Write([]byte("flow 1"))
	require.NoError(t, err)
	st1, _ := acceptFlow(t, sess)
	_, err = protocol.ReadDatagram(st1, nil)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return logs.count(slog.LevelError, "panic recovered") >= 1 },
		6*time.Second, 5*time.Millisecond, "the panic is logged")
	require.Eventually(t, func() bool { return mgr.limiter.Visitors() == 0 }, 6*time.Second, 5*time.Millisecond,
		"the slot of the flow is returned although closing its stream panicked")
	// The stream itself is still there, its Close never got through: it
	// keeps its place in the total.
	require.Equal(t, 1, mgr.limiter.Total())

	// The sweeper is still at work: the next flow idles out as well.
	_, err = visitor(t, port).Write([]byte("flow 2"))
	require.NoError(t, err)
	st2, _ := acceptFlow(t, sess)
	_, err = protocol.ReadDatagram(st2, nil)
	require.NoError(t, err)
	_ = st2.(net.Conn).SetReadDeadline(time.Now().Add(8 * time.Second))
	_, err = protocol.ReadDatagram(st2, nil)
	require.Error(t, err)
	var ne net.Error
	require.False(t, errors.As(err, &ne) && ne.Timeout(), "the second flow was never evicted: the sweeper is gone")

	// Once the first flow's stream ends, its place in the total comes back
	// (its drain recovers the panic of the same Close).
	require.NoError(t, st1.Close())
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond,
		"the place of the first flow's stream did not come back when the stream ended")
}

// A flow whose stream the backend ends is evicted by its reader. When closing
// the stream panics in that eviction, the stream's hold on the total is given
// back all the same: eviction and retirement are separate deferred calls.
func TestAPanicWhileAFlowEndsDoesNotKeepItsTotalSlot(t *testing.T) {
	logs := &logCapture{}
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, Logger: slog.New(logs), IdleTimeout: time.Minute, SweepInterval: time.Minute})
	sess := newScriptSession()
	sess.wrap = func(s protocol.Stream) protocol.Stream { return closePanicStream{s.(net.Conn)} }
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer func() {
		defer func() { _ = recover() }()
		mgr.Close(port)
	}()

	_, err = visitor(t, port).Write([]byte("hello"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	_, err = protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, 1, mgr.limiter.Total())

	require.NoError(t, st.Close()) // the backend ends the flow's stream
	require.Eventually(t, func() bool { return logs.count(slog.LevelError, "panic recovered") >= 1 },
		6*time.Second, 5*time.Millisecond, "the panic is logged")
	require.Eventually(t, func() bool { return mgr.limiter.Visitors() == 0 && mgr.limiter.Total() == 0 },
		6*time.Second, 5*time.Millisecond, "the flow's place in the total leaked")
}
