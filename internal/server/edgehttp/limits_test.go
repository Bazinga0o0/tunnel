package edgehttp

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// --- options ------------------------------------------------------------------

func TestDefaultsAndDisabledSettings(t *testing.T) {
	def := New(Options{Domain: "localhost", Registry: registry.New()})
	require.Equal(t, 256, def.opts.MaxConnsPerTunnel)
	require.Equal(t, 64, def.opts.MaxConnsPerIP)
	require.Equal(t, 1000, def.opts.MaxConns)
	require.Equal(t, 5*time.Minute, def.opts.IdleTimeout)
	require.Equal(t, 65536, def.opts.MaxHeaderBytes)

	set := New(Options{Domain: "localhost", Registry: registry.New(),
		MaxConnsPerTunnel: 7, MaxConnsPerIP: 3, MaxConns: 9, IdleTimeout: time.Second, MaxHeaderBytes: 10000})
	require.Equal(t, 7, set.opts.MaxConnsPerTunnel)
	require.Equal(t, 3, set.opts.MaxConnsPerIP)
	require.Equal(t, 9, set.opts.MaxConns)
	require.Equal(t, time.Second, set.opts.IdleTimeout)
	require.Equal(t, 10000, set.opts.MaxHeaderBytes)

	// Negative disables; internally a disabled setting is zero.
	off := New(Options{Domain: "localhost", Registry: registry.New(),
		MaxConnsPerTunnel: -1, MaxConnsPerIP: -1, MaxConns: -1, IdleTimeout: -1, MaxHeaderBytes: -1})
	require.Zero(t, off.opts.MaxConnsPerTunnel)
	require.Zero(t, off.opts.MaxConnsPerIP)
	require.Zero(t, off.opts.MaxConns)
	require.Zero(t, off.opts.IdleTimeout)
	// The exception: the header limit cannot be disabled. A negative value
	// selects the default as well.
	require.Equal(t, 65536, off.opts.MaxHeaderBytes)

	// A header limit below the size of the read buffer could not be enforced
	// to the byte; it is raised to that size.
	small := New(Options{Domain: "localhost", Registry: registry.New(), MaxHeaderBytes: 100})
	require.Equal(t, 4096, small.opts.MaxHeaderBytes)
}

// --- connection limits -------------------------------------------------------------

// hold opens n visitor connections to host and completes one request on
// each, so that each is hijacked and stays open.
func hold(t *testing.T, f *fixture, sess *scriptSession, host string, n int) ([]*visitor, []*backend) {
	t.Helper()
	var visitors []*visitor
	var backends []*backend
	for i := 0; i < n; i++ {
		v := f.visit()
		v.send("GET /hold HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
		b := sess.accept(t)
		b.next()
		b.reply("held")
		v.recvOK("held")
		visitors = append(visitors, v)
		backends = append(backends, b)
	}
	return visitors, backends
}

// refused sends one request on a new connection and requires a 503.
func refused(t *testing.T, f *fixture, host string) {
	t.Helper()
	v := f.visit()
	v.send("GET /over HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	res, body := v.recv()
	require.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	require.Equal(t, "too many connections\n", body)
	require.True(t, res.Close, "the refused connection is not kept alive")
}

func TestConnLimitPerTunnel(t *testing.T) {
	f := newFixture(t, Options{MaxConnsPerTunnel: 2, MaxConnsPerIP: 100, MaxConns: 100})
	abc, other := f.tunnel("abc"), f.tunnel("other")

	visitors, backends := hold(t, f, abc, "abc.localhost", 2)
	before := requestCount(t, "limit_tunnel")
	proxied := requestCount(t, "proxied")

	refused(t, f, "abc.localhost")
	require.Equal(t, before+1, requestCount(t, "limit_tunnel"))
	require.Equal(t, proxied, requestCount(t, "proxied"), "a refused request is not counted as proxied")
	require.EqualValues(t, 2, abc.opens.Load(), "no stream is opened for a refused connection")
	require.Equal(t, 2, f.edge.limiter.Total())

	// Connections inside the limit keep working, the other tunnel has its own budget.
	visitors[0].send(get("/again"))
	backends[0].next()
	backends[0].reply("again")
	visitors[0].recvOK("again")
	hold(t, f, other, "other.localhost", 2)

	// A slot that is given back can be used again.
	require.NoError(t, visitors[1].c.Close())
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 3 }, 6*time.Second, 5*time.Millisecond)
	hold(t, f, abc, "abc.localhost", 1)
	refused(t, f, "abc.localhost")
}

func TestConnLimitPerSourceIP(t *testing.T) {
	f := newFixture(t, Options{MaxConnsPerTunnel: 100, MaxConnsPerIP: 2, MaxConns: 100})
	abc, other := f.tunnel("abc"), f.tunnel("other")

	hold(t, f, abc, "abc.localhost", 2)
	before := requestCount(t, "limit_ip")
	refused(t, f, "abc.localhost")
	require.Equal(t, before+1, requestCount(t, "limit_ip"))
	require.EqualValues(t, 2, abc.opens.Load())

	// The limit is per tunnel: the same source may use the other tunnel.
	hold(t, f, other, "other.localhost", 2)
}

func TestConnLimitTotal(t *testing.T) {
	f := newFixture(t, Options{MaxConnsPerTunnel: 100, MaxConnsPerIP: 100, MaxConns: 3})
	abc, other := f.tunnel("abc"), f.tunnel("other")

	hold(t, f, abc, "abc.localhost", 2)
	visitors, _ := hold(t, f, other, "other.localhost", 1)
	before := requestCount(t, "limit_total")
	refused(t, f, "abc.localhost")
	refused(t, f, "other.localhost")
	require.Equal(t, before+2, requestCount(t, "limit_total"))
	require.EqualValues(t, 2, abc.opens.Load())
	require.EqualValues(t, 1, other.opens.Load())

	require.NoError(t, visitors[0].c.Close())
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 2 }, 6*time.Second, 5*time.Millisecond)
	hold(t, f, abc, "abc.localhost", 1)
}

func TestDisabledConnLimits(t *testing.T) {
	f := newFixture(t, Options{MaxConnsPerTunnel: -1, MaxConnsPerIP: -1, MaxConns: -1})
	abc := f.tunnel("abc")
	// More connections from one source than the per-IP default of 64 allows.
	hold(t, f, abc, "abc.localhost", 70)
}

func TestDefaultConnLimitPerSourceIPIs64(t *testing.T) {
	f := newFixture(t, Options{})
	abc := f.tunnel("abc")

	hold(t, f, abc, "abc.localhost", 64)
	before := requestCount(t, "limit_ip")
	refused(t, f, "abc.localhost")
	require.Equal(t, before+1, requestCount(t, "limit_ip"))
	require.EqualValues(t, 64, abc.opens.Load())
}

// A refused request leaves an ordinary keep-alive connection behind on which
// the visitor may try again; that must work once a slot is free.
func TestRequestAfterLimitIsLiftedSucceeds(t *testing.T) {
	f := newFixture(t, Options{MaxConnsPerTunnel: 1})
	abc := f.tunnel("abc")

	visitors, _ := hold(t, f, abc, "abc.localhost", 1)
	refused(t, f, "abc.localhost")
	require.NoError(t, visitors[0].c.Close())
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
	hold(t, f, abc, "abc.localhost", 1)
}

// --- idle timeout -------------------------------------------------------------------

func TestIdleConnectionIsClosed(t *testing.T) {
	f := newFixture(t, Options{IdleTimeout: 400 * time.Millisecond})
	abc := f.tunnel("abc")

	start := time.Now() // before the last byte moves
	visitors, backends := hold(t, f, abc, "abc.localhost", 1)

	visitors[0].expectClosed(6*time.Second, "idle visitor connection")
	require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond, "closed before the idle timeout")
	backends[0].expectEnd(6*time.Second, "stream of the idle connection")
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

func TestIdleTimeoutIsExtendedByARequestBodyThatKeepsMoving(t *testing.T) {
	f := newFixture(t, Options{IdleTimeout: time.Second})
	abc := f.tunnel("abc")
	v := f.visit()

	// A body of 25 bytes, one every 100 ms: 2.5 s, two and a half times the
	// timeout. The backend says nothing during that time.
	v.send("POST /slow HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 25\r\n\r\n")
	b := abc.accept(t)
	go func() {
		for i := 0; i < 25; i++ {
			time.Sleep(100 * time.Millisecond)
			if _, err := v.c.Write([]byte{byte('a' + i)}); err != nil {
				return
			}
		}
	}()
	req := b.next()
	require.Equal(t, "abcdefghijklmnopqrstuvwxy", req.Body)
	b.reply("done")
	v.recvOK("done")

	v.expectClosed(6*time.Second, "connection after the traffic stopped")
}

func TestIdleTimeoutIsExtendedByAResponseThatKeepsMoving(t *testing.T) {
	f := newFixture(t, Options{IdleTimeout: time.Second})
	abc := f.tunnel("abc")
	v := f.visit()

	v.send(get("/stream"))
	b := abc.accept(t)
	b.next()

	// The backend streams a chunk every 100 ms for 2.5 s; the visitor only reads.
	b.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
	go func() {
		for i := 0; i < 25; i++ {
			time.Sleep(100 * time.Millisecond)
			if _, err := b.c.Write([]byte("1\r\n" + string(rune('a'+i)) + "\r\n")); err != nil {
				return
			}
		}
		_, _ = b.c.Write([]byte("0\r\n\r\n"))
	}()
	res, body := v.recv()
	require.Equal(t, 200, res.StatusCode)
	require.Equal(t, "abcdefghijklmnopqrstuvwxy", body)

	v.expectClosed(6*time.Second, "connection after the traffic stopped")
}

// The time spent forwarding a request body is bounded. A visitor that
// announces a body and then stops sending loses the connection.
func TestStalledRequestBodyEndsTheConnection(t *testing.T) {
	for _, position := range []string{"first request", "follow-up request"} {
		t.Run(position, func(t *testing.T) {
			f := newFixture(t, Options{IdleTimeout: 400 * time.Millisecond})
			abc := f.tunnel("abc")
			v := f.visit()

			var b *backend
			if position == "follow-up request" {
				v.send(get("/first"))
				b = abc.accept(t)
				b.next()
				b.reply("ok")
				v.recvOK("ok")
			}
			start := time.Now() // before the last byte moves
			v.send("POST /stall HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 1000\r\n\r\nonly this")
			if b == nil {
				b = abc.accept(t)
			}
			// The backend takes what the edge forwards: the edge waits for
			// the visitor, not for the backend.
			ended := make(chan error, 1)
			go func() {
				_ = b.c.SetReadDeadline(time.Now().Add(8 * time.Second))
				_, err := io.Copy(io.Discard, b.br)
				ended <- err
			}()

			v.expectClosed(6*time.Second, "connection with a stalled request body")
			require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
			require.NoError(t, <-ended, "the stream of the stalled request was left open")
			require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
		})
	}
}

func TestIdleTimeoutDisabled(t *testing.T) {
	f := newFixture(t, Options{IdleTimeout: -1})
	abc := f.tunnel("abc")

	visitors, backends := hold(t, f, abc, "abc.localhost", 1)
	visitors[0].expectOpen(600*time.Millisecond, "connection without idle timeout")
	visitors[0].send(get("/still-open"))
	backends[0].next()
	backends[0].reply("yes")
	visitors[0].recvOK("yes")
}

// --- error paths ------------------------------------------------------------------------

func TestOpenStreamFailureGets502AndIsLoggedOncePerInterval(t *testing.T) {
	f := newFixture(t, Options{})
	abc := f.tunnel("abc")
	abc.openHook = func(int32) error { return errors.New("internal detail: session 0xdeadbeef is gone") }

	const attempts = 20
	for i := 0; i < attempts; i++ {
		v := f.visit()
		v.send(get("/"))
		res, body := v.recv()
		require.Equal(t, http.StatusBadGateway, res.StatusCode)
		require.Equal(t, "tunnel stream error\n", body, "the client gets a fixed text, not the internal error")
	}
	require.EqualValues(t, attempts, abc.opens.Load())
	require.Equal(t, 1, f.logs.count(slog.LevelWarn, "open stream failed"),
		"%d failed opens within one interval produce one warning", attempts)
	require.Zero(t, f.edge.limiter.Total(), "a failed open releases its slot")
}

func TestStreamHeaderWriteFailureEndsTheConnectionAndIsLoggedOncePerInterval(t *testing.T) {
	f := newFixture(t, Options{})
	abc := f.tunnel("abc")

	const attempts = 10
	for i := 0; i < attempts; i++ {
		v := f.visit()
		v.send(get("/"))
		select {
		case st := <-abc.streams:
			require.NoError(t, st.Close()) // the backend goes away before it reads the header
		case <-time.After(6 * time.Second):
			t.Fatal("no stream was opened")
		}
		v.expectClosed(6*time.Second, "connection whose stream died")
	}
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
	require.Equal(t, 1, f.logs.count(slog.LevelWarn, "write header failed"),
		"%d failed header writes within one interval produce one warning", attempts)
}

// panicStream panics on read or on the nth write.
type panicStream struct {
	net.Conn     // the stream; embedding the conn keeps its deadline methods
	onRead       bool
	panicOnWrite int32 // 1-based write that panics; 0 never
	writes       atomic.Int32
}

func (p *panicStream) Read(b []byte) (int, error) {
	if p.onRead {
		panic("boom in stream read")
	}
	return p.Conn.Read(b)
}

func (p *panicStream) Write(b []byte) (int, error) {
	if n := p.writes.Add(1); p.panicOnWrite != 0 && n >= p.panicOnWrite {
		panic("boom in stream write")
	}
	return p.Conn.Write(b)
}

func TestPanicInEitherDirectionDoesNotEndTheProcess(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wrap    func(protocol.Stream) protocol.Stream
		logged  string
		atLevel slog.Level
		times   int
	}{
		// The response copy runs in a goroutine of the edge: the edge has to
		// recover. The drain of the retired stream reads it too, and its
		// panic is recovered and logged as well.
		{"response copy", func(s protocol.Stream) protocol.Stream { return &panicStream{Conn: s.(net.Conn), onRead: true} },
			"panic recovered", slog.LevelError, 2},
		// The request direction runs in the goroutine of the HTTP server,
		// which recovers and logs on its own. The stream header takes two
		// writes; the third write is the request.
		{"request forwarding", func(s protocol.Stream) protocol.Stream { return &panicStream{Conn: s.(net.Conn), panicOnWrite: 3} },
			"panic serving", slog.LevelError, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, Options{})
			abc := f.tunnel("abc")
			abc.wrap = func(s protocol.Stream) protocol.Stream {
				if abc.opens.Load() == 1 {
					return tc.wrap(s)
				}
				return s
			}

			v := f.visit()
			v.send(get("/boom"))
			b := abc.accept(t)
			go func() { _, _ = io.Copy(io.Discard, b.c) }()
			v.expectClosed(6*time.Second, "connection whose handler panicked")
			require.Eventually(t, func() bool { return f.logs.count(tc.atLevel, tc.logged) == tc.times },
				6*time.Second, 5*time.Millisecond, "the panic is logged")
			require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)

			// The edge keeps serving.
			hold(t, f, abc, "abc.localhost", 1)
		})
	}
}
