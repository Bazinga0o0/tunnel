package edgeudp

import (
	"context"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// Further cases from the attack list: sequences, boundaries and error paths.

func TestCloseIsIdempotentAndDatagramsAfterCloseAreHarmless(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute})
	sess := newScriptSession()

	mgr.Close(ports[0]) // never opened

	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	v := visitor(t, port)
	_, err = v.Write([]byte("one"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	_, err = protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, 1, mgr.limiter.Total())

	mgr.Close(port)
	mgr.Close(port)
	require.Zero(t, mgr.limiter.Visitors(), "Close returns the slots of all flows")
	// The place of the flow's stream in the total comes back when the stream
	// is gone: its drain ends as soon as the closed pipe fails its read.
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)

	// The stream of the flow is closed towards the backend.
	_, err = protocol.ReadDatagram(st, nil)
	require.Error(t, err)

	// Datagrams to the closed port go nowhere and start nothing.
	_, _ = v.Write([]byte("after close"))
	time.Sleep(50 * time.Millisecond)
	require.EqualValues(t, 1, sess.opens.Load())
	require.Zero(t, mgr.limiter.Total())
}

func TestStreamHeaderDescribesTheVisitor(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := visitor(t, port)
	_, err = v.Write([]byte("hi"))
	require.NoError(t, err)
	_, hdr := acceptFlow(t, sess)
	require.Equal(t, protocol.StreamTypeUDP, hdr.StreamType)
	require.Equal(t, "127.0.0.1", hdr.RemoteIP)
	require.Equal(t, v.LocalAddr().(*net.UDPAddr).Port, hdr.RemotePort)
	require.NotEqual(t, hdr.RemotePort, hdr.PublicPort)
	require.Equal(t, port, hdr.PublicPort)
	require.EqualValues(t, 1, hdr.FlowID)
}

func TestExpiredFlowIsReplacedByAFreshOne(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, ReplyCredit: 2, IdleTimeout: 500 * time.Millisecond, SweepInterval: 20 * time.Millisecond})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := visitor(t, port)
	_, err = v.Write([]byte("first"))
	require.NoError(t, err)
	st1, hdr1 := acceptFlow(t, sess)
	_, err = protocol.ReadDatagram(st1, nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, hdr1.FlowID)

	// The flow idles out: its stream ends and its slot is returned.
	_, err = protocol.ReadDatagram(st1, nil)
	require.Error(t, err)
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)

	// The same visitor comes back: new stream, next flow id, fresh credit of two.
	_, err = v.Write([]byte("second"))
	require.NoError(t, err)
	st2, hdr2 := acceptFlow(t, sess)
	got, err := protocol.ReadDatagram(st2, nil)
	require.NoError(t, err)
	require.Equal(t, "second", string(got))
	require.EqualValues(t, 2, hdr2.FlowID)
	require.Equal(t, hdr1.RemotePort, hdr2.RemotePort)

	for i := 0; i < 5; i++ {
		require.NoError(t, protocol.WriteDatagram(st2, []byte{'r', byte('0' + i)}))
	}
	require.Equal(t, [][]byte{[]byte("r0"), []byte("r1")}, readAvailable(t, v, 2))
}

func TestDefaultMaxReplyCreditIs4096(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	// 17 inbound datagrams would pay for 17*256 = 4352 replies.
	v := visitor(t, port)
	_, err = v.Write([]byte("in"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	_, err = protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	for i := 1; i < 17; i++ {
		_, err = v.Write([]byte("in"))
		require.NoError(t, err)
		_, err = protocol.ReadDatagram(st, nil)
		require.NoError(t, err)
	}
	go func() { _, _ = io.Copy(io.Discard, v) }()

	before := requestCount(t, "reply_limit")
	for i := 0; i < 4200; i++ {
		require.NoError(t, protocol.WriteDatagram(st, []byte("r")))
	}
	require.Eventually(t, func() bool { return requestCount(t, "reply_limit") >= before+104 },
		6*time.Second, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, before+104, requestCount(t, "reply_limit"), "4096 of 4200 replies pass, 104 are dropped")
}

func TestReplyCreditDoesNotWrapWithoutCap(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, ReplyCredit: math.MaxInt, MaxReplyCredit: -1, IdleTimeout: time.Minute})
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
	for i := 0; i < 3; i++ { // each further grant would overflow an int
		_, err = v.Write([]byte("in"))
		require.NoError(t, err)
		_, err = protocol.ReadDatagram(st, nil)
		require.NoError(t, err)
	}
	require.NoError(t, protocol.WriteDatagram(st, []byte("reply")))
	require.Equal(t, [][]byte{[]byte("reply")}, readAvailable(t, v, 1))
}

func TestFullFlowBufferDropsAndDoesNotStallThePort(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, BufferSize: 2, IdleTimeout: time.Minute})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	// The backend reads the stream header of the first flow and the length
	// prefix of datagram 0, and then stops: the pump has taken datagram 0
	// out of the buffer and is stuck writing its payload.
	slow := visitor(t, port)
	_, err = slow.Write([]byte("0"))
	require.NoError(t, err)
	stuck, _ := acceptFlow(t, sess)
	_, err = io.ReadFull(stuck, make([]byte, 2))
	require.NoError(t, err)

	before := requestCount(t, "drop")
	for i := 1; i <= 9; i++ {
		_, err = slow.Write([]byte{byte('0' + i)})
		require.NoError(t, err)
	}
	// Two fit into the buffer, seven are dropped.
	require.Eventually(t, func() bool { return requestCount(t, "drop") == before+7 }, 6*time.Second, 10*time.Millisecond)

	// Another visitor is served meanwhile.
	v := visitor(t, port)
	_, err = v.Write([]byte("ping"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	got, err := protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, "ping", string(got))
}

// panicStream panics on every read.
type panicStream struct {
	net.Conn // the stream; embedding the conn keeps its deadline methods
}

func (p panicStream) Read([]byte) (int, error) { panic("boom in stream read") }

func TestPanicInFlowReaderDoesNotEndTheProcess(t *testing.T) {
	logs := &logCapture{}
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, Logger: slog.New(logs), IdleTimeout: time.Minute})
	sess := newScriptSession()
	sess.wrap = func(s protocol.Stream) protocol.Stream {
		if sess.opens.Load() == 1 {
			return panicStream{s.(net.Conn)}
		}
		return s
	}
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	_, err = visitor(t, port).Write([]byte("flow with the broken stream"))
	require.NoError(t, err)
	acceptFlow(t, sess)
	// Twice: the drain of the retired stream reads it too, and its panic is
	// recovered and logged as well.
	require.Eventually(t, func() bool { return logs.count(slog.LevelError, "panic recovered") == 2 },
		6*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 10*time.Millisecond,
		"the flow whose reader panicked is gone")

	v := visitor(t, port)
	_, err = v.Write([]byte("ping"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	got, err := protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, "ping", string(got))
}

func TestPanicInSocketReadDoesNotEndTheProcess(t *testing.T) {
	logs := &logCapture{}
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40002, 40002), Logger: slog.New(logs)})
	conn := newFakePacketConn(func(n int) ([]byte, netip.AddrPort, error, bool) {
		if n == 1 {
			panic("boom in socket read")
		}
		return nil, netip.AddrPort{}, nil, true
	})
	mgr.listen = func(int) (packetConn, error) { return conn, nil }
	port, err := mgr.Open(context.Background(), 0, newScriptSession())
	require.NoError(t, err)
	defer mgr.Close(port)

	require.Eventually(t, func() bool { return logs.count(slog.LevelError, "panic recovered") == 1 },
		6*time.Second, 10*time.Millisecond)
}

func TestStreamHeaderWriteFailureReleasesTheFlow(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	v := visitor(t, port)
	_, err = v.Write([]byte("x"))
	require.NoError(t, err)
	// The backend closes the stream instead of reading the header.
	select {
	case st := <-sess.streams:
		require.NoError(t, st.Close())
	case <-time.After(6 * time.Second):
		t.Fatal("no flow was opened")
	}
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 10*time.Millisecond)

	// The next datagram of the visitor starts over.
	_, err = v.Write([]byte("again"))
	require.NoError(t, err)
	st, _ := acceptFlow(t, sess)
	got, err := protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, "again", string(got))
}
