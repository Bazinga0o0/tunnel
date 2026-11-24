package edgeudp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
)

// --- a panic in the read loop ----------------------------------------------------

// A panic at loop level must not leave the port bound but dead: the loop is
// entered again and the next datagram is served.
func TestReadLoopIsEnteredAgainAfterAPanic(t *testing.T) {
	logs := &logCapture{}
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40004, 40004), Logger: slog.New(logs), IdleTimeout: time.Minute})
	src := netip.MustParseAddrPort("192.0.2.1:5353")
	conn := newFakePacketConn(func(n int) ([]byte, netip.AddrPort, error, bool) {
		switch n {
		case 1:
			panic("read went wrong")
		case 2:
			return []byte("a datagram"), src, nil, false
		}
		return nil, netip.AddrPort{}, nil, true
	})
	mgr.listen = func(int) (packetConn, error) { return conn, nil }

	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	st, hdr := acceptFlow(t, sess)
	require.Equal(t, "192.0.2.1", hdr.RemoteIP)
	got, err := protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, "a datagram", string(got))
	require.Equal(t, 1, logs.count(slog.LevelError, "panic recovered"))
}

// A loop that panics every time is retried with the pauses of the backoff,
// and Close still ends it.
func TestReadLoopPanicsBackOff(t *testing.T) {
	logs := &logCapture{}
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40005, 40005), Logger: slog.New(logs)})
	conn := newFakePacketConn(func(int) ([]byte, netip.AddrPort, error, bool) { panic("read went wrong") })
	mgr.listen = func(int) (packetConn, error) { return conn, nil }

	port, err := mgr.Open(context.Background(), 0, newScriptSession())
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	mgr.Close(port)

	// 5+10+20+40+80+160 ms: the seventh read would start after 315 ms.
	calls := len(conn.callTimes())
	require.GreaterOrEqual(t, calls, 2, "the loop is entered again after a panic")
	require.LessOrEqual(t, calls, 8, "a panicking loop is retried with growing pauses, not in a tight loop")
	require.Equal(t, 1, logs.count(slog.LevelError, "panic recovered"), "and its panics are logged once per interval")

	time.Sleep(150 * time.Millisecond)
	require.LessOrEqual(t, len(conn.callTimes()), calls+1, "Close ends the loop")
}

// Panics that alternate with successful reads get the shortest pause every
// time, because a success resets the backoff. Their log lines, each with a
// stack, go through a limiter that counts what it holds back.
func TestReadLoopPanicsAreLoggedThroughALimiter(t *testing.T) {
	logs := &logCapture{}
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40018, 40018), Logger: slog.New(logs), IdleTimeout: time.Minute})
	sess := newScriptSession()
	sess.openHook = func(int32) error { return errors.New("session is gone") }

	start := make(chan struct{})
	var panics atomic.Int32
	src := netip.MustParseAddrPort("192.0.2.1:5353")
	conn := newFakePacketConn(func(n int) ([]byte, netip.AddrPort, error, bool) {
		<-start
		if n%2 == 1 {
			panics.Add(1)
			panic("read went wrong")
		}
		return []byte("a datagram"), src, nil, false
	})
	mgr.listen = func(int) (packetConn, error) { return conn, nil }
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)

	// A shorter interval than the five seconds of production. The loop has
	// not touched the limiter yet: its first read waits for start.
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

// --- BindHost ------------------------------------------------------------------

func TestBindHostSelectsTheListenAddress(t *testing.T) {
	pool, ports := testPorts(t, 1)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: pool, IdleTimeout: time.Minute})
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	mgr.mu.Lock()
	addr := mgr.byPort[port].conn.(*net.UDPConn).LocalAddr().(*net.UDPAddr)
	mgr.mu.Unlock()
	require.True(t, addr.IP.IsLoopback(), "listening on %v", addr)
	require.Equal(t, "127.0.0.1", addr.IP.String())
	require.Equal(t, port, addr.Port)

	v := visitor(t, port)
	_, err = v.Write([]byte("ping"))
	require.NoError(t, err)
	st, hdr := acceptFlow(t, sess)
	require.Equal(t, "127.0.0.1", hdr.RemoteIP)
	got, err := protocol.ReadDatagram(st, nil)
	require.NoError(t, err)
	require.Equal(t, "ping", string(got))
	require.NoError(t, protocol.WriteDatagram(st, []byte("pong")))
	require.Equal(t, [][]byte{[]byte("pong")}, readAvailable(t, v, 1))
}

func TestBindHostMustBeAnIPAddress(t *testing.T) {
	for _, host := range []string{"localhost", "example.com", "127.0.0.1:80", "127.0.0.1/8", "[::1]", " 127.0.0.1", "0x7f.1", "127.1", "*"} {
		t.Run(host, func(t *testing.T) {
			pool, ports := testPorts(t, 1)
			mgr := New(Options{BindHost: host, Pool: pool})
			listened := false
			mgr.listen = func(int) (packetConn, error) {
				listened = true
				return newFakePacketConn(func(int) ([]byte, netip.AddrPort, error, bool) {
					return nil, netip.AddrPort{}, nil, true
				}), nil
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
	all := listenAddress(netip.Addr{}, 8080)
	require.Nil(t, all.IP)
	require.Equal(t, 8080, all.Port)

	v4 := listenAddress(netip.MustParseAddr("127.0.0.1"), 8080)
	require.Equal(t, "127.0.0.1:8080", v4.String())
	v6 := listenAddress(netip.MustParseAddr("::1"), 8080)
	require.Equal(t, "[::1]:8080", v6.String())
}
