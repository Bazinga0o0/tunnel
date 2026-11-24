package connector

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// startUDPEcho runs a local UDP echo server (the "game host").
func startUDPEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			payload := append([]byte(nil), buf[:n]...)
			_, _ = echo.WriteToUDP(payload, addr)
		}
	}()
	return echo
}

func udpHeader() *protocol.StreamHeader {
	return &protocol.StreamHeader{
		StreamType: protocol.StreamTypeUDP,
		RemoteIP:   "1.2.3.4",
		RemotePort: 54321,
		PublicPort: 7000,
		FlowID:     42,
	}
}

// newUDPConnector builds a connector for a udp tunnel to the given local
// service.
func newUDPConnector(local *net.UDPConn, idle time.Duration) *Connector {
	return New(Options{
		LocalAddr:      local.LocalAddr().String(),
		ExpectedType:   protocol.StreamTypeUDP,
		UDPIdleTimeout: idle,
	})
}

// roundTrip sends one datagram into the flow and expects it echoed back.
func roundTrip(t *testing.T, serverSide protocol.Stream, payload string) {
	t.Helper()
	require.NoError(t, protocol.WriteDatagram(serverSide, []byte(payload)))
	setReadDeadline(t, serverSide, 5*time.Second)
	got, err := protocol.ReadDatagram(serverSide, make([]byte, 4096))
	require.NoError(t, err)
	require.Equal(t, payload, string(got))
}

// The timing tests below use an idle time that is at least ten times the
// interval between datagrams, and they measure lower bounds from a point
// before the last datagram, so that a slow machine cannot make them fail.
// The upper bound is the 10 s limit of result: it only has to tell "closed
// after the idle time" from "never closed".

func TestHandleUDPEchoes(t *testing.T) {
	echo := startUDPEcho(t)

	a, b := protocol.PipeStream()
	c := New(Options{LocalAddr: echo.LocalAddr().String(), ExpectedType: protocol.StreamTypeUDP, DialTimeout: time.Second})

	// Driver writes a UDP stream into "a" as if it were the server-side end.
	done := make(chan struct{})
	go func() {
		defer close(done)
		require.NoError(t, c.Handle(b))
	}()

	// Server side: write header + datagram, read echoed datagram.
	require.NoError(t, protocol.WriteStreamHeader(a, udpHeader()))
	require.NoError(t, protocol.WriteDatagram(a, []byte("ping")))

	scratch := make([]byte, 4096)
	got, err := protocol.ReadDatagram(a, scratch)
	require.NoError(t, err)
	require.Equal(t, []byte("ping"), got)

	_ = a.Close()
	<-done
}

func TestHandleUDPWithExpectedType(t *testing.T) {
	echo := startUDPEcho(t)
	serverSide, clientSide := protocol.PipeStream()
	c := New(Options{LocalAddr: echo.LocalAddr().String(), ExpectedType: protocol.StreamTypeUDP})
	done := handleAsync(c, clientSide)

	require.NoError(t, protocol.WriteStreamHeader(serverSide, udpHeader()))
	roundTrip(t, serverSide, "first")
	roundTrip(t, serverSide, "second")

	_ = serverSide.Close()
	require.NoError(t, result(t, done, 5*time.Second))
}

// A flow nobody uses any more is closed by the client itself; it does not
// wait for the server to do so.
func TestHandleUDPClosesIdleFlow(t *testing.T) {
	const idle = time.Second
	echo := startUDPEcho(t)
	serverSide, clientSide := protocol.PipeStream()
	done := handleAsync(newUDPConnector(echo, idle), clientSide)

	require.NoError(t, protocol.WriteStreamHeader(serverSide, udpHeader()))
	beforeLast := time.Now()
	roundTrip(t, serverSide, "only one")

	require.NoError(t, result(t, done, 10*time.Second))
	assert.GreaterOrEqual(t, time.Since(beforeLast), idle, "closed before the idle time was over")
	expectClosed(t, serverSide)
}

// The idle time counts from the last datagram, not from the start of the
// flow: a datagram half way through the idle time moves the close back by
// the full idle time.
func TestHandleUDPIdleTimeCountsFromLastDatagram(t *testing.T) {
	const idle = 2 * time.Second
	echo := startUDPEcho(t)
	serverSide, clientSide := protocol.PipeStream()
	done := handleAsync(newUDPConnector(echo, idle), clientSide)

	require.NoError(t, protocol.WriteStreamHeader(serverSide, udpHeader()))
	time.Sleep(idle / 2)
	beforeLast := time.Now()
	roundTrip(t, serverSide, "half way")

	require.NoError(t, result(t, done, 10*time.Second))
	assert.GreaterOrEqual(t, time.Since(beforeLast), idle,
		"closed one idle time after the flow started instead of one idle time after its last datagram")
	expectClosed(t, serverSide)
}

// Datagrams from the server keep the flow open well beyond the idle timeout.
func TestHandleUDPInboundTrafficKeepsFlowOpen(t *testing.T) {
	const idle = 1500 * time.Millisecond
	echo := startUDPEcho(t)
	serverSide, clientSide := protocol.PipeStream()
	done := handleAsync(newUDPConnector(echo, idle), clientSide)

	require.NoError(t, protocol.WriteStreamHeader(serverSide, udpHeader()))
	// A round trip every 100 ms for 2.2 s, well past the idle time.
	start := time.Now()
	for time.Since(start) < idle+700*time.Millisecond {
		roundTrip(t, serverSide, "tick")
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("flow was closed although it was in use: %v", err)
	default:
	}

	require.NoError(t, result(t, done, 10*time.Second))
	expectClosed(t, serverSide)
}

// Datagrams from the server keep the flow open even when the local service
// never answers.
func TestHandleUDPInboundOnlyTrafficKeepsFlowOpen(t *testing.T) {
	const idle = 1500 * time.Millisecond
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	defer sink.Close()
	var (
		mu       sync.Mutex
		received int
	)
	go func() {
		buf := make([]byte, 64)
		for {
			if _, _, err := sink.ReadFromUDP(buf); err != nil {
				return
			}
			mu.Lock()
			received++
			mu.Unlock()
		}
	}()

	serverSide, clientSide := protocol.PipeStream()
	done := handleAsync(newUDPConnector(sink, idle), clientSide)

	require.NoError(t, protocol.WriteStreamHeader(serverSide, udpHeader()))
	// 22 datagrams, 100 ms apart: 2.1 s of one-way traffic, past the idle time.
	const datagrams = 22
	for i := 0; i < datagrams; i++ {
		require.NoError(t, protocol.WriteDatagram(serverSide, []byte("tick")), "datagram %d: flow was closed although it was in use", i)
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("flow was closed although it was in use: %v", err)
	default:
	}
	// The last datagrams may still be on their way to the local socket.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return received == datagrams
	}, 5*time.Second, 10*time.Millisecond, "the local service did not get every datagram")

	require.NoError(t, result(t, done, 10*time.Second))
	expectClosed(t, serverSide)
}

// Datagrams from the local service alone keep the flow open as well.
func TestHandleUDPOutboundTrafficKeepsFlowOpen(t *testing.T) {
	const idle = 1500 * time.Millisecond
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	defer local.Close()

	serverSide, clientSide := protocol.PipeStream()
	done := handleAsync(newUDPConnector(local, idle), clientSide)

	require.NoError(t, protocol.WriteStreamHeader(serverSide, udpHeader()))
	require.NoError(t, protocol.WriteDatagram(serverSide, []byte("hello")))

	// The local service learns the flow's address from the first datagram
	// and then streams on its own.
	_ = local.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, flowAddr, err := local.ReadFromUDP(buf)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buf[:n]))

	// 25 datagrams, 100 ms apart: 2.4 s of traffic in one direction only.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 25; i++ {
			_, _ = local.WriteToUDP([]byte("push"), flowAddr)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// The 21st datagram is sent 2 s after the first one, 0.5 s past the idle
	// time counted from "hello". Without the outbound traffic the flow would
	// be gone by then.
	start := time.Now()
	for i := 0; i < 21; i++ {
		setReadDeadline(t, serverSide, 5*time.Second)
		got, err := protocol.ReadDatagram(serverSide, make([]byte, 64))
		require.NoError(t, err, "flow was closed although the local service was sending (datagram %d)", i)
		require.Equal(t, "push", string(got))
	}
	assert.Greater(t, time.Since(start), idle)
	wg.Wait()

	// Once the local service stops, the flow goes idle and is closed.
	require.NoError(t, result(t, done, 10*time.Second))
}

func TestHandleUDPIdleTimeoutDisabledByNegativeValue(t *testing.T) {
	echo := startUDPEcho(t)
	serverSide, clientSide := protocol.PipeStream()
	done := handleAsync(newUDPConnector(echo, -1), clientSide)

	require.NoError(t, protocol.WriteStreamHeader(serverSide, udpHeader()))
	roundTrip(t, serverSide, "one")
	stillRunning(t, done, 800*time.Millisecond)
	roundTrip(t, serverSide, "two")

	_ = serverSide.Close()
	require.NoError(t, result(t, done, 5*time.Second))
}
