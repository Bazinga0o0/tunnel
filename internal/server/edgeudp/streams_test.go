package edgeudp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// bareStream is a stream without deadline methods, as a wrapper around a
// tunnel stream would be that forgot to pass them on.
type bareStream struct {
	s protocol.Stream
}

func (b bareStream) Read(p []byte) (int, error)  { return b.s.Read(p) }
func (b bareStream) Write(p []byte) (int, error) { return b.s.Write(p) }
func (b bareStream) Close() error                { return b.s.Close() }

// Ending a flow works through a deadline on its stream. A stream that cannot
// take a deadline is refused: using it would leave the flow's reader waiting
// for the tunnel client without anyone noticing.
func TestStreamWithoutDeadlinesIsRefused(t *testing.T) {
	logs := &logCapture{}
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, Logger: slog.New(logs), IdleTimeout: time.Minute})
	sess := newScriptSession()
	sess.wrap = func(s protocol.Stream) protocol.Stream { return bareStream{s} }
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	before := requestCount(t, "stream_rejected")
	const attempts = 5
	for i := 0; i < attempts; i++ {
		_, err = visitor(t, port).Write([]byte("hello"))
		require.NoError(t, err)

		// The stream is closed again and nothing was sent on it.
		select {
		case st := <-sess.streams:
			c := st.(net.Conn)
			_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
			n, err := io.Copy(io.Discard, c)
			var ne net.Error
			require.False(t, errors.As(err, &ne) && ne.Timeout(), "the refused stream was left open")
			require.Zero(t, n, "the refused stream was used")
		case <-time.After(6 * time.Second):
			t.Fatal("no stream was opened")
		}
	}
	require.Eventually(t, func() bool { return requestCount(t, "stream_rejected") == before+attempts },
		6*time.Second, 5*time.Millisecond, "every refused stream is counted")
	require.Equal(t, 1, logs.count(slog.LevelWarn, "stream refused"), "%d refusals within one interval produce one warning", attempts)
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}
