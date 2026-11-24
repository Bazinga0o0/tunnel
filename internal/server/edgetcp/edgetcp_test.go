package edgetcp

import (
	"context"
	"io"
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

func TestManagerEchoesBytes(t *testing.T) {
	pool, ports := testPorts(t, 11) // a free range: fixed ranges collide with ports the system reserves
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})

	fake := &fakeSession{incoming: make(chan protocol.Stream, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port, err := mgr.Open(ctx, 0, fake)
	require.NoError(t, err)
	require.GreaterOrEqual(t, port, ports[0])
	require.LessOrEqual(t, port, ports[len(ports)-1])
	defer mgr.Close(port)

	// Backend: when the public side connects, the fake session hands us a
	// stream; read the header + request bytes, echo back.
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream := <-fake.incoming
		defer stream.Close()

		hdr, err := protocol.ReadStreamHeader(stream)
		require.NoError(t, err)
		require.Equal(t, protocol.StreamTypeTCP, hdr.StreamType)
		require.Equal(t, port, hdr.PublicPort)

		buf := make([]byte, 4)
		_, _ = io.ReadFull(stream, buf)
		_, _ = stream.Write(buf)
	}()

	// Public side: dial the listener.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, "ping", string(buf))

	<-done
}

func TestManagerCloseReturnsPortToPool(t *testing.T) {
	pool, _ := testPorts(t, 1) // a free port: fixed ranges collide with ports the system reserves
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})
	fake := &fakeSession{incoming: make(chan protocol.Stream, 1)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port, err := mgr.Open(ctx, 0, fake)
	require.NoError(t, err)

	// Pool exhausted.
	_, err = mgr.Open(ctx, 0, fake)
	require.ErrorIs(t, err, ErrPoolExhausted)

	mgr.Close(port)

	// Port returned to pool.
	port2, err := mgr.Open(ctx, 0, fake)
	require.NoError(t, err)
	require.Equal(t, port, port2)
	mgr.Close(port2)
}
