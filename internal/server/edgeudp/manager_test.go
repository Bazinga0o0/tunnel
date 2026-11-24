package edgeudp

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

type fakeSession struct {
	incoming chan protocol.Stream
}

func (f *fakeSession) OpenStream() (protocol.Stream, error) {
	a, b := protocol.PipeStream()
	f.incoming <- a
	return b, nil
}

func TestManagerEchoesDatagram(t *testing.T) {
	pool, ports := testPorts(t, 1) // a free port: fixed ranges collide with ports the system reserves
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Second, BufferSize: 8, SweepInterval: 100 * time.Millisecond})

	fake := &fakeSession{incoming: make(chan protocol.Stream, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port, err := mgr.Open(ctx, ports[0], fake)
	require.NoError(t, err)
	defer mgr.Close(port)

	// Backend goroutine: reads StreamHeader + datagram, echoes back.
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream := <-fake.incoming
		defer stream.Close()

		hdr, err := protocol.ReadStreamHeader(stream)
		require.NoError(t, err)
		require.Equal(t, protocol.StreamTypeUDP, hdr.StreamType)
		require.Equal(t, port, hdr.PublicPort)
		require.NotZero(t, hdr.FlowID)
		require.Equal(t, "127.0.0.1", hdr.RemoteIP)

		buf := make([]byte, 4096)
		payload, err := protocol.ReadDatagram(stream, buf)
		require.NoError(t, err)
		require.Equal(t, []byte("ping"), payload)
		require.NoError(t, protocol.WriteDatagram(stream, []byte("pong")))
	}()

	// Public side.
	conn, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(port))
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "pong", string(buf[:n]))

	<-done
}

func TestManagerCloseReturnsPortToPool(t *testing.T) {
	pool, ports := testPorts(t, 1) // a free port: fixed ranges collide with ports the system reserves
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute, BufferSize: 8, SweepInterval: time.Minute})
	fake := &fakeSession{incoming: make(chan protocol.Stream, 8)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port, err := mgr.Open(ctx, ports[0], fake)
	require.NoError(t, err)

	_, err = mgr.Open(ctx, 0, fake)
	require.ErrorIs(t, err, ErrPoolExhausted)

	mgr.Close(port)

	port2, err := mgr.Open(ctx, ports[0], fake)
	require.NoError(t, err)
	require.Equal(t, port, port2)
	mgr.Close(port2)
}

func TestManagerIdleSweepClosesFlow(t *testing.T) {
	pool, ports := testPorts(t, 1) // a free port: fixed ranges collide with ports the system reserves
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 200 * time.Millisecond, BufferSize: 8, SweepInterval: 50 * time.Millisecond})
	fake := &fakeSession{incoming: make(chan protocol.Stream, 1)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port, err := mgr.Open(ctx, ports[0], fake)
	require.NoError(t, err)
	defer mgr.Close(port)

	conn, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(port))
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("hi"))
	require.NoError(t, err)

	stream := <-fake.incoming
	// Drain header + first datagram.
	_, err = protocol.ReadStreamHeader(stream)
	require.NoError(t, err)
	buf := make([]byte, 4096)
	_, err = protocol.ReadDatagram(stream, buf)
	require.NoError(t, err)

	// Wait past idle timeout, expect stream to be closed (next ReadDatagram errors).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, err = protocol.ReadDatagram(stream, buf)
		if err != nil {
			return
		}
	}
	t.Fatal("flow stream still open after idle timeout")
}
