package edgetcp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
)

// records returns the captured records of a level whose message contains msgPart.
func (c *logCapture) records(level slog.Level, msgPart string) []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []slog.Record
	for _, r := range c.recs {
		if r.Level == level && strings.Contains(r.Message, msgPart) {
			out = append(out, r)
		}
	}
	return out
}

// attr returns the value of the attribute key of a record.
func attr(r slog.Record, key string) string {
	value := ""
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			value = a.Value.String()
			return false
		}
		return true
	})
	return value
}

// --- a panic in the accept loop ------------------------------------------------

// A panic at loop level must not leave the port bound but dead: the loop is
// entered again and the next connection is served.
func TestAcceptLoopIsEnteredAgainAfterAPanic(t *testing.T) {
	logs := &logCapture{}
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: NewPool(40014, 40014), Logger: slog.New(logs)})
	visitorEnd, edgeEnd := net.Pipe()
	defer visitorEnd.Close()
	ln := newFakeListener(func(n int) (net.Conn, error, bool) {
		switch n {
		case 1:
			panic("accept went wrong")
		case 2:
			return edgeEnd, nil, false
		}
		return nil, nil, true
	})
	mgr.listen = func(int) (net.Listener, error) { return ln, nil }

	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	b, _ := acceptStream(t, sess)
	exchange(t, visitorEnd, b, "served")
	require.Equal(t, 1, logs.count(slog.LevelError, "panic recovered"))
}

// A loop that panics every time is retried with the pauses of the backoff,
// and Close still ends it.
func TestAcceptLoopPanicsBackOff(t *testing.T) {
	logs := &logCapture{}
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: NewPool(40015, 40015), Logger: slog.New(logs)})
	ln := newFakeListener(func(int) (net.Conn, error, bool) { panic("accept went wrong") })
	mgr.listen = func(int) (net.Listener, error) { return ln, nil }

	port, err := mgr.Open(context.Background(), 0, newScriptSession())
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	mgr.Close(port)

	// 5+10+20+40+80+160 ms: the seventh Accept would start after 315 ms.
	calls := len(ln.callTimes())
	require.GreaterOrEqual(t, calls, 2, "the loop is entered again after a panic")
	require.LessOrEqual(t, calls, 8, "a panicking loop is retried with growing pauses, not in a tight loop")
	require.Equal(t, 1, logs.count(slog.LevelError, "panic recovered"), "and its panics are logged once per interval")

	time.Sleep(150 * time.Millisecond)
	require.LessOrEqual(t, len(ln.callTimes()), calls+1, "Close ends the loop")
}

// Panics that alternate with successful accepts get the shortest pause every
// time, because a success resets the backoff. Their log lines, each with a
// stack, go through a limiter that counts what it holds back.
func TestAcceptLoopPanicsAreLoggedThroughALimiter(t *testing.T) {
	logs := &logCapture{}
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: NewPool(40016, 40016), Logger: slog.New(logs)})
	sess := newScriptSession()
	sess.openHook = func(int32) error { return errors.New("session is gone") }

	start := make(chan struct{})
	var panics atomic.Int32
	ln := newFakeListener(func(n int) (net.Conn, error, bool) {
		<-start
		if n%2 == 1 {
			panics.Add(1)
			panic("accept went wrong")
		}
		visitorEnd, edgeEnd := net.Pipe()
		_ = visitorEnd.Close()
		return edgeEnd, nil, false
	})
	mgr.listen = func(int) (net.Listener, error) { return ln, nil }
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)

	// A shorter interval than the five seconds of production. The loop has
	// not touched the limiter yet: its first Accept waits for start.
	const interval = 150 * time.Millisecond
	mgr.mu.Lock()
	mgr.byPort[port].panicLog = edgeguard.NewLogLimiter(interval)
	mgr.mu.Unlock()
	began := time.Now()
	close(start)
	time.Sleep(500 * time.Millisecond)
	mgr.Close(port)
	elapsed := time.Since(began)

	recs := logs.records(slog.LevelError, "panic recovered")
	require.GreaterOrEqual(t, int(panics.Load()), 8, "the loop panicked every few milliseconds")
	require.GreaterOrEqual(t, len(recs), 2)
	require.LessOrEqual(t, len(recs), 1+int(elapsed/interval), "one line per interval")
	require.Equal(t, "0", attr(recs[0], "suppressed"), "the first panic is always logged")
	require.NotEqual(t, "0", attr(recs[1], "suppressed"), "the panics held back are counted")
	require.NotEmpty(t, attr(recs[1], "stack"))
}

// --- BindHost ------------------------------------------------------------------

func TestBindHostSelectsTheListenAddress(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	mgr.mu.Lock()
	addr := mgr.byPort[port].listener.Addr().(*net.TCPAddr)
	mgr.mu.Unlock()
	require.True(t, addr.IP.IsLoopback(), "listening on %v", addr)
	require.Equal(t, "127.0.0.1", addr.IP.String())
	require.Equal(t, port, addr.Port)

	v := dial(t, port)
	b, _ := acceptStream(t, sess)
	exchange(t, v, b, "ping")
}

func TestBindHostMustBeAnIPAddress(t *testing.T) {
	for _, host := range []string{"localhost", "example.com", "127.0.0.1:80", "127.0.0.1/8", "[::1]", " 127.0.0.1", "0x7f.1", "127.1", "*"} {
		t.Run(host, func(t *testing.T) {
			pool, ports := testPorts(t, 1)
			mgr := NewWithOptions(Options{BindHost: host, Pool: pool})
			listened := false
			mgr.listen = func(int) (net.Listener, error) {
				listened = true
				return newFakeListener(func(int) (net.Conn, error, bool) { return nil, nil, true }), nil
			}
			_, err := mgr.Open(context.Background(), ports[0], newScriptSession())
			require.Error(t, err)
			require.Contains(t, err.Error(), "BindHost")
			require.False(t, listened, "nothing is opened for a bind host that is not an IP address")

			// The refused Open took no port from the pool.
			p, err := pool.Allocate(ports[0])
			require.NoError(t, err)
			require.Equal(t, ports[0], p)
		})
	}
}

// An empty BindHost is the wildcard address, as before the option existed.
func TestEmptyBindHostListensOnAllInterfaces(t *testing.T) {
	require.Equal(t, ":8080", listenAddress("", 8080))
	require.Equal(t, "127.0.0.1:8080", listenAddress("127.0.0.1", 8080))
	require.Equal(t, "[::1]:8080", listenAddress("::1", 8080))
}
