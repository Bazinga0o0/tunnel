package edgeudp

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// --- helpers ---------------------------------------------------------------

type datagram struct {
	data []byte
	src  netip.AddrPort
}

// feedSocket returns a socket that hands the read loop the datagrams sent to
// feed, one per read. The read loop reads again only after it has dealt with
// the datagram before, so once read n+1 has started, datagram n is through.
func feedSocket(t *testing.T) (conn *fakePacketConn, feed chan<- datagram) {
	t.Helper()
	ch := make(chan datagram, 256)
	t.Cleanup(func() { close(ch) })
	conn = newFakePacketConn(func(int) ([]byte, netip.AddrPort, error, bool) {
		d, ok := <-ch
		if !ok {
			return nil, netip.AddrPort{}, nil, true
		}
		return d.data, d.src, nil, false
	})
	return conn, ch
}

// waitDispatched waits until the read loop has dealt with n datagrams.
func waitDispatched(t *testing.T, conn *fakePacketConn, n int) {
	t.Helper()
	require.Eventually(t, func() bool { return len(conn.callTimes()) >= n+1 }, 6*time.Second, time.Millisecond,
		"the read loop did not get through %d datagrams", n)
}

func waitQueued(t *testing.T, mgr *Manager, want int64) {
	t.Helper()
	require.Eventually(t, func() bool { return mgr.queued.Load() == want }, 6*time.Second, time.Millisecond,
		"queued bytes: want %d, have %d", want, mgr.queued.Load())
}

func filled(c byte, n int) []byte { return bytes.Repeat([]byte{c}, n) }

// onlyFlow returns the single flow of the listener on port.
func onlyFlow(t *testing.T, mgr *Manager, port int) *flow {
	t.Helper()
	mgr.mu.Lock()
	al := mgr.byPort[port]
	mgr.mu.Unlock()
	require.NotNil(t, al)
	al.mu.Lock()
	defer al.mu.Unlock()
	require.Len(t, al.flows, 1)
	for _, f := range al.flows {
		return f
	}
	return nil
}

// stuckFlow starts a flow with the one-byte datagram "0" from src and leaves
// the backend in the middle of that datagram: it has read the stream header
// and the length prefix, so the pump is stuck writing the payload.
func stuckFlow(t *testing.T, conn *fakePacketConn, feed chan<- datagram, sess *scriptSession, src netip.AddrPort) protocol.Stream {
	t.Helper()
	feed <- datagram{[]byte("0"), src}
	st, _ := acceptFlow(t, sess)
	_, err := io.ReadFull(st, make([]byte, 2))
	require.NoError(t, err)
	return st
}

// --- reply credit and the queue ------------------------------------------------

// The credit for the replies to a datagram exists before the datagram can
// reach the backend. Granted afterwards, the reply of a fast backend meets a
// flow without credit and is dropped.
func TestReplyCreditIsGrantedBeforeTheDatagramIsQueued(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, ReplyCredit: 1, IdleTimeout: time.Minute})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := visitor(t, port)
	_, err = v.Write([]byte("first"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	got, err := protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, "first", string(got))
	// The reply uses up the credit of the first datagram.
	require.NoError(t, protocol.WriteDatagram(st, []byte("reply 1")))
	require.Equal(t, [][]byte{[]byte("reply 1")}, readAvailable(t, v, 1))
	f := onlyFlow(t, mgr, port)

	// While the test holds the flow's lock no credit can be granted. A
	// datagram that reaches the backend now was queued without its credit.
	arrived := make(chan []byte, 1)
	go func() {
		got, _ := protocol.ReadDatagram(st, nil)
		arrived <- got
	}()
	f.mu.Lock()
	_, err = v.Write([]byte("second"))
	require.NoError(t, err)
	select {
	case got := <-arrived:
		credit := f.credit
		f.mu.Unlock()
		require.Equal(t, "second", string(got))
		require.Equal(t, 1, credit, "the datagram reached the backend before the credit for its reply was granted")
	case <-time.After(300 * time.Millisecond):
		// Queueing and granting are one step under the flow's lock.
		f.mu.Unlock()
		select {
		case got := <-arrived:
			require.Equal(t, "second", string(got))
		case <-time.After(6 * time.Second):
			t.Fatal("the second datagram did not reach the backend")
		}
	}

	require.NoError(t, protocol.WriteDatagram(st, []byte("reply 2")))
	require.Equal(t, [][]byte{[]byte("reply 2")}, readAvailable(t, v, 1))
}

// A datagram that is dropped because the flow's buffer is full pays for no
// reply and does not count as activity of the visitor.
func TestDroppedDatagramGrantsNoCreditAndIsNoActivity(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40006, 40006), BufferSize: 2, ReplyCredit: 1, MaxReplyCredit: 100,
		IdleTimeout: time.Minute, SweepInterval: time.Minute})
	conn, feed := feedSocket(t)
	mgr.listen = func(int) (packetConn, error) { return conn, nil }
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)
	src := netip.MustParseAddrPort("192.0.2.1:4000")

	stuckFlow(t, conn, feed, sess, src)
	feed <- datagram{[]byte("1"), src}
	feed <- datagram{[]byte("2"), src}
	waitDispatched(t, conn, 3)
	f := onlyFlow(t, mgr, port)
	f.mu.Lock()
	credit, lastSeen := f.credit, f.lastSeen
	f.mu.Unlock()
	require.Equal(t, 3, credit, "one in transit and two in the buffer")

	before := requestCount(t, "drop")
	time.Sleep(20 * time.Millisecond)
	for i := 0; i < 7; i++ {
		feed <- datagram{[]byte("x"), src}
	}
	waitDispatched(t, conn, 10)
	require.Equal(t, before+7, requestCount(t, "drop"))
	// The dropped datagrams were booked in the byte budgets of port and
	// manager before the full buffer refused them, and are given back at both
	// levels: what remains is the one byte in transit and the two buffered.
	require.EqualValues(t, 3, mgr.queued.Load(), "manager")
	require.EqualValues(t, mgr.queued.Load(), listenerOf(t, mgr, port).queued.Load(), "the port agrees with the manager")
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Equal(t, 3, f.credit, "a dropped datagram grants no credit")
	require.Equal(t, lastSeen, f.lastSeen, "a dropped datagram does not keep the flow alive")
}

// --- byte budget of the queues -------------------------------------------------

func TestQueueBudgetDefaultsAndDisabled(t *testing.T) {
	pool := NewPool(40007, 40007)

	def := New(Options{BindHost: "127.0.0.1", Pool: pool})
	require.Equal(t, 256<<10, def.opts.MaxQueuedBytesPerFlow)
	require.Equal(t, 2<<20, def.opts.MaxQueuedBytesPerPort)
	require.Equal(t, 64<<20, def.opts.MaxQueuedBytes)

	set := New(Options{BindHost: "127.0.0.1", Pool: pool, MaxQueuedBytesPerFlow: 700, MaxQueuedBytesPerPort: 800, MaxQueuedBytes: 900})
	require.Equal(t, 700, set.opts.MaxQueuedBytesPerFlow)
	require.Equal(t, 800, set.opts.MaxQueuedBytesPerPort)
	require.Equal(t, 900, set.opts.MaxQueuedBytes)

	// Negative disables; internally a disabled setting is zero.
	off := New(Options{BindHost: "127.0.0.1", Pool: pool, MaxQueuedBytesPerFlow: -1, MaxQueuedBytesPerPort: -1, MaxQueuedBytes: -1})
	require.Zero(t, off.opts.MaxQueuedBytesPerFlow)
	require.Zero(t, off.opts.MaxQueuedBytesPerPort)
	require.Zero(t, off.opts.MaxQueuedBytes)
}

// listenerOf returns the listener of port.
func listenerOf(t *testing.T, mgr *Manager, port int) *activeListener {
	t.Helper()
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	al := mgr.byPort[port]
	require.NotNil(t, al)
	return al
}

// One tunnel must not be able to use up the queue budget of the manager: the
// flows of a port share a budget of their own, and a second port still gets
// its datagrams through while the first is full.
func TestQueuedBytesPerPortAreBounded(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40015, 40016), IdleTimeout: time.Minute,
		MaxQueuedBytesPerFlow: -1, MaxQueuedBytesPerPort: 2500, MaxQueuedBytes: 4000})
	conn1, feed1 := feedSocket(t)
	conn2, feed2 := feedSocket(t)
	sockets := []packetConn{conn1, conn2}
	mgr.listen = func(int) (packetConn, error) {
		conn := sockets[0]
		sockets = sockets[1:]
		return conn, nil
	}
	sess1, sess2 := newScriptSession(), newScriptSession()
	port1, err := mgr.Open(context.Background(), 0, sess1)
	require.NoError(t, err)
	defer mgr.Close(port1)
	port2, err := mgr.Open(context.Background(), 0, sess2)
	require.NoError(t, err)
	defer mgr.Close(port2)
	al1, al2 := listenerOf(t, mgr, port1), listenerOf(t, mgr, port2)
	a, b, c := netip.MustParseAddrPort("192.0.2.1:4000"), netip.MustParseAddrPort("192.0.2.2:4000"), netip.MustParseAddrPort("192.0.2.3:4000")

	// The tunnel client of the first port does not take its datagrams. Three
	// sources send to it: 1 + 2*1000 bytes fit into the port's 2500, the
	// other three datagrams do not, whichever flow they belong to.
	before := requestCount(t, "limit_buffer")
	stuckFlow(t, conn1, feed1, sess1, a)
	for _, src := range []netip.AddrPort{a, a, b, c, a} {
		feed1 <- datagram{filled('1', 1000), src}
	}
	waitDispatched(t, conn1, 6)
	require.Equal(t, before+3, requestCount(t, "limit_buffer"), "datagrams beyond the port's byte budget are dropped and counted")
	require.EqualValues(t, 2001, al1.queued.Load())
	require.EqualValues(t, 2001, mgr.queued.Load(), "the first port has not used up the budget of the manager")

	// The second port is not affected.
	d := netip.MustParseAddrPort("192.0.2.4:4000")
	feed2 <- datagram{filled('2', 1000), d}
	st2, _ := acceptFlow(t, sess2)
	got, err := protocol.ReadDatagram(st2, nil)
	require.NoError(t, err)
	require.Equal(t, filled('2', 1000), got)
	waitDispatched(t, conn2, 1)
	require.Equal(t, before+3, requestCount(t, "limit_buffer"), "no datagram of the second port is refused")
	require.Eventually(t, func() bool { return al2.queued.Load() == 0 }, 6*time.Second, time.Millisecond)
	waitQueued(t, mgr, 2001)

	// The flows of the first port end: their bytes are given back, at both
	// levels and exactly once.
	mgr.Close(port1)
	waitQueued(t, mgr, 0)
	require.Never(t, func() bool { return mgr.queued.Load() != 0 || al1.queued.Load() != 0 }, 100*time.Millisecond, 5*time.Millisecond,
		"the bytes of a closed port are given back exactly once")
}

// The default budget of a port is 2 MiB.
func TestDefaultQueueBudgetPerPortIs2MiB(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40017, 40017), IdleTimeout: time.Minute, MaxQueuedBytesPerFlow: -1})
	conn, feed := feedSocket(t)
	mgr.listen = func(int) (packetConn, error) { return conn, nil }
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)
	src := netip.MustParseAddrPort("192.0.2.1:4000")

	stuckFlow(t, conn, feed, sess, src)
	before := requestCount(t, "limit_buffer")
	for i := 0; i < 36; i++ {
		feed <- datagram{filled('x', 60000), src}
	}
	waitDispatched(t, conn, 37)
	// 1 + 34*60000 = 2040001 bytes fit into 2097152, the next datagram does not.
	require.Equal(t, before+2, requestCount(t, "limit_buffer"))
	require.EqualValues(t, 2040001, listenerOf(t, mgr, port).queued.Load())
}

func TestQueuedBytesPerFlowAreBounded(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40008, 40008), MaxQueuedBytesPerFlow: 3000, IdleTimeout: time.Minute})
	conn, feed := feedSocket(t)
	mgr.listen = func(int) (packetConn, error) { return conn, nil }
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)
	src := netip.MustParseAddrPort("192.0.2.1:4000")

	st := stuckFlow(t, conn, feed, sess, src)
	beforeLimit, beforeDrop := requestCount(t, "limit_buffer"), requestCount(t, "drop")
	for i := 1; i <= 9; i++ {
		feed <- datagram{filled(byte('0'+i), 1000), src}
	}
	waitDispatched(t, conn, 10)
	// One byte is in transit; two datagrams of 1000 bytes fit into 3000 on
	// top of it, seven do not.
	require.Equal(t, beforeLimit+7, requestCount(t, "limit_buffer"), "datagrams beyond the flow's byte budget are dropped and counted")
	require.Equal(t, beforeDrop, requestCount(t, "drop"), "they are not counted as buffer drops")
	require.EqualValues(t, 2001, mgr.queued.Load())

	// The backend reads on: what was queued arrives in order.
	rest := make([]byte, 1)
	_, err = io.ReadFull(st, rest)
	require.NoError(t, err)
	require.Equal(t, "0", string(rest))
	for i := 1; i <= 2; i++ {
		got, err := protocol.ReadDatagram(st, nil)
		require.NoError(t, err)
		require.Equal(t, filled(byte('0'+i), 1000), got)
	}
	waitQueued(t, mgr, 0)

	// The budget is free again; exactly 3000 bytes fit.
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 3; i++ {
			if _, err := protocol.ReadDatagram(st, nil); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 3; i++ {
		feed <- datagram{filled('n', 1000), src}
	}
	waitDispatched(t, conn, 13)
	require.NoError(t, <-done)
	require.Equal(t, beforeLimit+7, requestCount(t, "limit_buffer"))
	waitQueued(t, mgr, 0)
}

// A budget below the datagram size must not silence a flow: with nothing
// waiting, a datagram of any size passes.
func TestDatagramLargerThanTheBudgetPassesWhenNothingIsQueued(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"per flow", Options{MaxQueuedBytesPerFlow: 100}},
		{"per port", Options{MaxQueuedBytesPerFlow: -1, MaxQueuedBytesPerPort: 100}},
		{"per manager", Options{MaxQueuedBytesPerFlow: -1, MaxQueuedBytesPerPort: -1, MaxQueuedBytes: 100}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			opts.BindHost, opts.Pool, opts.IdleTimeout = "127.0.0.1", NewPool(40009+i, 40009+i), time.Minute
			mgr := New(opts)
			conn, feed := feedSocket(t)
			mgr.listen = func(int) (packetConn, error) { return conn, nil }
			sess := newScriptSession()
			port, err := mgr.Open(context.Background(), 0, sess)
			require.NoError(t, err)
			defer mgr.Close(port)
			src := netip.MustParseAddrPort("192.0.2.1:4000")

			feed <- datagram{filled('a', 5000), src}
			st, _ := acceptFlow(t, sess)
			got, err := protocol.ReadDatagram(st, nil)
			require.NoError(t, err)
			require.Equal(t, filled('a', 5000), got)
			waitQueued(t, mgr, 0)

			// The backend reads only the length prefix of the next one: its
			// 5000 bytes are still waiting, and nothing fits beside them.
			feed <- datagram{filled('b', 5000), src}
			_, err = io.ReadFull(st, make([]byte, 2))
			require.NoError(t, err)
			before := requestCount(t, "limit_buffer")
			feed <- datagram{[]byte("small"), src}
			waitDispatched(t, conn, 3)
			require.Equal(t, before+1, requestCount(t, "limit_buffer"))
			require.EqualValues(t, 5000, mgr.queued.Load())

			rest := make([]byte, 5000)
			_, err = io.ReadFull(st, rest)
			require.NoError(t, err)
			require.Equal(t, filled('b', 5000), rest)
			waitQueued(t, mgr, 0)

			feed <- datagram{[]byte("small again"), src}
			got, err = protocol.ReadDatagram(st, nil)
			require.NoError(t, err)
			require.Equal(t, "small again", string(got))
		})
	}
}

func TestQueuedBytesPerManagerAreBounded(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40011, 40011), MaxQueuedBytesPerFlow: -1, MaxQueuedBytes: 2500, IdleTimeout: time.Minute})
	conn, feed := feedSocket(t)
	mgr.listen = func(int) (packetConn, error) { return conn, nil }
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	a, b := netip.MustParseAddrPort("192.0.2.1:4000"), netip.MustParseAddrPort("192.0.2.2:4000")

	stuckFlow(t, conn, feed, sess, a)
	feed <- datagram{filled('1', 1000), a}
	feed <- datagram{filled('2', 1000), a}
	waitDispatched(t, conn, 3)
	require.EqualValues(t, 2001, mgr.queued.Load())

	// Another flow has nothing waiting of its own, but the budget of the
	// manager is used up by the first.
	before := requestCount(t, "limit_buffer")
	feed <- datagram{filled('b', 1000), b}
	waitDispatched(t, conn, 4)
	require.Equal(t, before+1, requestCount(t, "limit_buffer"), "datagrams beyond the manager's byte budget are dropped and counted")
	require.EqualValues(t, 2001, mgr.queued.Load())
	// The port had booked the refused datagram before the manager refused
	// it, and has given it back.
	require.EqualValues(t, 2001, listenerOf(t, mgr, port).queued.Load(), "the port's bytes after the manager's refusal")

	// What still fits is delivered: 2001 + 499 = 2500.
	stB, _ := acceptFlow(t, sess)
	feed <- datagram{filled('c', 499), b}
	got, err := protocol.ReadDatagram(stB, nil)
	require.NoError(t, err)
	require.Equal(t, filled('c', 499), got)
	waitQueued(t, mgr, 2001)

	// Closing the listener gives back what its flows had waiting.
	mgr.Close(port)
	waitQueued(t, mgr, 0)
	require.Never(t, func() bool { return mgr.queued.Load() != 0 }, 100*time.Millisecond, 5*time.Millisecond,
		"the bytes of a closed flow are given back exactly once")
}

// A flow that ends gives back the bytes that were waiting in it.
func TestQueuedBytesAreReturnedWhenTheFlowEnds(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40012, 40012), IdleTimeout: time.Minute})
	conn, feed := feedSocket(t)
	mgr.listen = func(int) (packetConn, error) { return conn, nil }
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)
	src := netip.MustParseAddrPort("192.0.2.1:4000")

	st := stuckFlow(t, conn, feed, sess, src)
	feed <- datagram{filled('1', 1000), src}
	feed <- datagram{filled('2', 1000), src}
	waitDispatched(t, conn, 3)
	al := listenerOf(t, mgr, port)
	require.EqualValues(t, 2001, mgr.queued.Load())
	require.EqualValues(t, 2001, al.queued.Load())

	// The backend drops the stream: the pump fails in the middle of a
	// datagram and the flow is evicted with two more in its buffer.
	require.NoError(t, st.Close())
	waitQueued(t, mgr, 0)
	require.Never(t, func() bool { return mgr.queued.Load() != 0 || al.queued.Load() != 0 }, 100*time.Millisecond, 5*time.Millisecond,
		"the bytes of an ended flow are given back exactly once, to the port and to the manager")
}

// The default budget of a flow is 256 KiB: 64 datagrams of the largest size
// no longer fit into the buffer of one flow.
func TestDefaultQueueBudgetPerFlowIs256KiB(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40013, 40013), IdleTimeout: time.Minute})
	conn, feed := feedSocket(t)
	mgr.listen = func(int) (packetConn, error) { return conn, nil }
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)
	src := netip.MustParseAddrPort("192.0.2.1:4000")

	stuckFlow(t, conn, feed, sess, src)
	before := requestCount(t, "limit_buffer")
	for i := 0; i < 6; i++ {
		feed <- datagram{filled('x', 60000), src}
	}
	waitDispatched(t, conn, 7)
	// 1 + 4*60000 = 240001 bytes fit into 262144, the fifth datagram does not.
	require.Equal(t, before+2, requestCount(t, "limit_buffer"))
	require.EqualValues(t, 240001, mgr.queued.Load())
}

// With all three budgets disabled only the number of datagrams bounds the buffer.
func TestQueueBudgetDisabled(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40014, 40014), IdleTimeout: time.Minute,
		MaxQueuedBytesPerFlow: -1, MaxQueuedBytesPerPort: -1, MaxQueuedBytes: -1})
	conn, feed := feedSocket(t)
	mgr.listen = func(int) (packetConn, error) { return conn, nil }
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)
	src := netip.MustParseAddrPort("192.0.2.1:4000")

	stuckFlow(t, conn, feed, sess, src)
	before := requestCount(t, "limit_buffer")
	// 40 datagrams of 60000 bytes: more than the default of a flow and more
	// than the default of a port.
	for i := 0; i < 40; i++ {
		feed <- datagram{filled('x', 60000), src}
	}
	waitDispatched(t, conn, 41)
	require.Equal(t, before, requestCount(t, "limit_buffer"))
	require.EqualValues(t, 40*60000+1, mgr.queued.Load())
}
