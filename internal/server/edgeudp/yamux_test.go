package edgeudp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// yamuxSession opens real yamux streams and reports when a read on the
// edge's end of a stream has returned an error.
type yamuxSession struct {
	sess      protocol.Session
	readEnded chan struct{}
}

func (y *yamuxSession) OpenStream() (protocol.Stream, error) {
	st, err := y.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	return &watchedStream{Stream: st, ended: y.readEnded}, nil
}

type watchedStream struct {
	protocol.Stream
	once  sync.Once
	ended chan struct{}
}

func (w *watchedStream) Read(p []byte) (int, error) {
	n, err := w.Stream.Read(p)
	if err != nil {
		w.once.Do(func() { close(w.ended) })
	}
	return n, err
}

// SetDeadline passes the deadline on to the yamux stream. A wrapper that
// hides it would take the edge's only means to end a blocked read.
func (w *watchedStream) SetDeadline(t time.Time) error {
	return w.Stream.(interface{ SetDeadline(time.Time) error }).SetDeadline(t)
}

// A yamux stream keeps serving reads after the edge closed its side. An
// evicted flow must not leave a goroutine behind that waits for a tunnel
// client that says nothing.
func TestEvictedFlowDoesNotWaitForTheTunnelClient(t *testing.T) {
	c1, c2 := net.Pipe()
	server, err := protocol.NewServerSession(c1)
	require.NoError(t, err)
	client, err := protocol.NewClientSession(c2)
	require.NoError(t, err)
	defer server.Close()
	defer client.Close()

	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: 300 * time.Millisecond, SweepInterval: 20 * time.Millisecond})
	sess := &yamuxSession{sess: server, readEnded: make(chan struct{})}
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	// The tunnel client takes the stream and the datagram, then neither
	// sends nor closes.
	taken := make(chan error, 1)
	go func() {
		st, err := client.AcceptStream()
		if err != nil {
			taken <- err
			return
		}
		if _, err := protocol.ReadStreamHeader(st); err != nil {
			taken <- err
			return
		}
		_, err = protocol.ReadDatagram(st, nil)
		taken <- err
	}()

	_, err = visitor(t, port).Write([]byte("hello"))
	require.NoError(t, err)
	select {
	case err := <-taken:
		require.NoError(t, err)
	case <-time.After(6 * time.Second):
		t.Fatal("the datagram did not reach the tunnel client")
	}

	// The flow idles out. Its reader, blocked in a read on the stream, ends.
	require.Eventually(t, func() bool { return mgr.limiter.Visitors() == 0 }, 6*time.Second, 5*time.Millisecond)
	select {
	case <-sess.readEnded:
	case <-time.After(6 * time.Second):
		t.Fatal("the reader of the evicted flow is still waiting for the tunnel client")
	}
	// The stream the tunnel client keeps open holds its place in the total
	// until it is gone: here until the session ends.
	require.Equal(t, 1, mgr.limiter.Total())
	require.NoError(t, server.Close())
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}
