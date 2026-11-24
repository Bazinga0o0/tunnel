package edgehttp

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// inDrain reports whether the calling goroutine is edgeguard's drain.
func inDrain() bool {
	buf := make([]byte, 8<<10)
	n := runtime.Stack(buf, false)
	return bytes.Contains(buf[:n], []byte("edgeguard.drain("))
}

// slowCloseStream models what makes a retired yamux stream's EOF come
// before the stream is gone: its Close ends the stream for readers at once
// (yamux sets the state first) and returns only later (yamux's sendClose).
// A Close of the edge takes 100 ms, the drain's own 20 ms. It counts the
// drain reads that end the stream while a Close of the edge is still under
// way: the drain would give the slot back then. The nth write panics.
type slowCloseStream struct {
	net.Conn
	panicOnWrite int32
	writes       atomic.Int32
	closing      atomic.Int32 // Closes of the edge under way
	early        atomic.Int32
}

func (s *slowCloseStream) Close() error {
	wait := 20 * time.Millisecond
	if !inDrain() {
		s.closing.Add(1)
		defer s.closing.Add(-1)
		wait = 100 * time.Millisecond
	}
	err := s.Conn.Close()
	time.Sleep(wait)
	return err
}

func (s *slowCloseStream) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if err != nil && inDrain() && s.closing.Load() > 0 {
		s.early.Add(1)
	}
	return n, err
}

func (s *slowCloseStream) Write(p []byte) (int, error) {
	if n := s.writes.Add(1); s.panicOnWrite != 0 && n >= s.panicOnWrite {
		panic("boom in stream write")
	}
	return s.Conn.Write(p)
}

// When forwarding a request panics, the response copy may still be running
// and still close the stream. The stream is retired only after that
// goroutine has returned: no Close of the edge may still be under way when
// the drain sees the stream end.
func TestAPanicRetiresTheStreamOnlyAfterTheResponseCopyHasReturned(t *testing.T) {
	f := newFixture(t, Options{})
	abc := f.tunnel("abc")
	wrapped := make(chan *slowCloseStream, 1)
	abc.wrap = func(s protocol.Stream) protocol.Stream {
		w := &slowCloseStream{Conn: s.(net.Conn), panicOnWrite: 3} // header: two writes
		wrapped <- w
		return w
	}

	v := f.visit()
	v.send(get("/boom"))
	b := abc.accept(t)
	go func() { _, _ = io.Copy(io.Discard, b.c) }()
	w := <-wrapped
	v.expectClosed(6*time.Second, "connection whose handler panicked")
	require.Eventually(t, func() bool { return f.logs.count(slog.LevelError, "panic serving") == 1 },
		6*time.Second, 5*time.Millisecond, "the panic is logged")
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
	require.Zero(t, w.early.Load(), "the drain saw the stream end while a Close of the edge was under way")
}
