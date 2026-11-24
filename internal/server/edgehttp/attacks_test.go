package edgehttp

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// Further cases from the attack list. Some need a visitor with another
// address than 127.0.0.1 or without TLS; those call the handler with a
// response writer that hands out an in-memory connection.

// pipeWriter is an http.ResponseWriter whose connection can be hijacked.
type pipeWriter struct {
	*httptest.ResponseRecorder
	edgeEnd net.Conn
}

func (w *pipeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.edgeEnd, bufio.NewReadWriter(bufio.NewReader(w.edgeEnd), bufio.NewWriter(w.edgeEnd)), nil
}

// call runs one GET request from remoteAddr through the edge. If the edge
// answers without hijacking, the recorded response is returned; otherwise
// the visitor's end of the connection. done is closed when the handler
// returns.
func call(t *testing.T, e *Edge, host, remoteAddr string) (rec *httptest.ResponseRecorder, visitorEnd net.Conn, done chan struct{}) {
	t.Helper()
	visitorEnd, edgeEnd := net.Pipe()
	t.Cleanup(func() { _ = visitorEnd.Close() })
	w := &pipeWriter{ResponseRecorder: httptest.NewRecorder(), edgeEnd: edgeEnd}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = host
	r.RemoteAddr = remoteAddr
	done = make(chan struct{})
	go func() {
		defer close(done)
		e.ServeHTTP(w, r)
	}()
	return w.ResponseRecorder, visitorEnd, done
}

func TestForwardingHeadersDescribeTheActualConnection(t *testing.T) {
	for remoteAddr, wantIP := range map[string]string{
		"203.0.113.9:5555":      "203.0.113.9",
		"[2001:db8::7]:443":     "2001:db8::7",
		"[::ffff:192.0.2.1]:80": "192.0.2.1", // IPv4-mapped is reported as IPv4
	} {
		t.Run(remoteAddr, func(t *testing.T) {
			reg := registry.New()
			e := New(Options{Domain: "localhost", Registry: reg})
			sess := &scriptSession{id: "s1", streams: make(chan protocol.Stream, 4)}
			require.NoError(t, reg.RegisterHTTP("abc", sess))

			_, visitorEnd, done := call(t, e, "abc.localhost", remoteAddr)
			b := sess.accept(t)
			require.Equal(t, wantIP, b.hdr.RemoteIP)
			require.Equal(t, "http", b.hdr.Scheme, "the request did not arrive over TLS")
			req := b.next()
			require.Equal(t, []string{wantIP}, req.Header["X-Forwarded-For"])
			require.Equal(t, []string{"http"}, req.Header["X-Forwarded-Proto"])
			require.Equal(t, []string{"abc.localhost"}, req.Header["X-Forwarded-Host"])

			require.NoError(t, visitorEnd.Close())
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				t.Fatal("the handler did not return after the visitor closed")
			}
			require.Zero(t, e.limiter.Visitors())
			// The stream's place in the total is given back by its drain,
			// which ends as soon as the closed pipe fails its read.
			require.Eventually(t, func() bool { return e.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
		})
	}
}

func TestConnLimitPerSourceCountsAddressesNotPorts(t *testing.T) {
	reg := registry.New()
	e := New(Options{Domain: "localhost", Registry: reg, MaxConnsPerTunnel: 100, MaxConnsPerIP: 2, MaxConns: 100})
	sess := &scriptSession{id: "s1", streams: make(chan protocol.Stream, 16)}
	require.NoError(t, reg.RegisterHTTP("abc", sess))

	var mu sync.Mutex
	var served []string
	before := requestCount(t, "limit_ip")
	for _, tc := range []struct {
		remoteAddr string
		accepted   bool
	}{
		{"10.0.0.1:1000", true},
		{"10.0.0.1:1001", true},
		{"10.0.0.1:1002", false}, // third connection of 10.0.0.1
		{"10.0.0.2:1000", true},  // another address has its own budget
		{"[::ffff:10.0.0.2]:1001", true},
		{"[::ffff:10.0.0.2]:1002", false}, // IPv4-mapped is the same address
		{"[2001:db8:1:2::1]:1000", true},
		{"[2001:db8:1:2:ffff::2]:1000", true},
		{"[2001:db8:1:2::3]:1000", false}, // third connection of one /64
		{"[2001:db8:1:3::1]:1000", true},  // another /64 has its own budget
		{"not-an-address", true},
		{"also not an address", true},
		{"still none", false}, // addresses that cannot be parsed share one budget
	} {
		rec, _, done := call(t, e, "abc.localhost", tc.remoteAddr)
		if !tc.accepted {
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				t.Fatalf("%s: no answer", tc.remoteAddr)
			}
			require.Equal(t, http.StatusServiceUnavailable, rec.Code, tc.remoteAddr)
			require.Equal(t, "too many connections\n", rec.Body.String())
			continue
		}
		b := sess.accept(t)
		mu.Lock()
		served = append(served, b.hdr.RemoteIP)
		mu.Unlock()
		go func() { _, _ = io.Copy(io.Discard, b.c) }()
	}
	require.Equal(t, before+4, requestCount(t, "limit_ip"))
	require.Equal(t, 9, e.limiter.Total())
	sort.Strings(served)
	require.Equal(t, []string{
		"", "", // a peer without a parsable address is reported as unknown
		"10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.2", "2001:db8:1:2::1", "2001:db8:1:2:ffff::2", "2001:db8:1:3::1",
	}, served)
}

func TestStreamHeaderCarriesTheNormalisedHost(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send("GET / HTTP/1.1\r\nHost: ABC.Localhost.:443\r\n" + forged + "\r\n")
	b := sess.accept(t)
	require.Equal(t, "abc.localhost", b.hdr.OriginalHost)
	req := b.next()
	require.Equal(t, "ABC.Localhost.:443", req.Host, "the Host header itself is passed on as sent")
	requireEdgeForwarding(t, req.Request, "abc.localhost")
}

// The header limit counts from the first byte of the request, also when
// part of the request was read together with the one before it.
func TestHeadLimitCountsBytesThatWereAlreadyBuffered(t *testing.T) {
	for _, tc := range []struct {
		name     string
		headSize int
		accepted bool
	}{
		{"exactly the limit", 8192, true},
		{"one byte more", 8193, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, Options{MaxHeaderBytes: 8192})
			sess := f.tunnel("abc")
			v := f.visit()

			// Three requests in one write: when the edge has read the second,
			// the beginning of the third is in its buffer already.
			big := paddedRequest(t, "/big", tc.headSize)
			go func() { _, _ = v.c.Write([]byte(get("/first") + get("/second") + big)) }()

			b := sess.accept(t)
			require.Equal(t, "/first", b.next().RequestURI)
			b.reply("1")
			require.Equal(t, "/second", b.next().RequestURI)
			if tc.accepted {
				b.reply("2")
				require.Equal(t, "/big", b.next().RequestURI)
				return
			}
			// The edge has given up on the connection by now or does so at
			// once; no answer is written into the dying stream.
			b.expectEnd(6*time.Second, "stream after an oversized request head")
		})
	}
}

// The idle timeout has to work when nobody waits on the visitor: the
// backend does not read, so the edge is stuck writing to the stream.
func TestIdleTimeoutCoversABackendThatDoesNotRead(t *testing.T) {
	t.Run("the request is not read", func(t *testing.T) {
		f := newFixture(t, Options{IdleTimeout: 400 * time.Millisecond})
		sess := f.tunnel("abc")
		v := f.visit()

		start := time.Now() // before the last byte moves
		v.send(get("/"))
		sess.accept(t) // reads the stream header and then nothing more
		v.expectClosed(6*time.Second, "connection to a backend that does not read")
		require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
		require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
	})

	t.Run("the stream header is not read", func(t *testing.T) {
		f := newFixture(t, Options{IdleTimeout: 400 * time.Millisecond})
		sess := f.tunnel("abc")
		v := f.visit()

		start := time.Now() // before the last byte moves
		v.send(get("/"))
		v.expectClosed(6*time.Second, "connection whose stream header is never read")
		require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
		require.EqualValues(t, 1, sess.opens.Load())
		require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
	})
}

// A visitor that sends its request and then closes its sending side still
// gets the answer.
func TestVisitorHalfCloseStillGetsTheResponse(t *testing.T) {
	f := newFixture(t, Options{})

	c1, c2 := net.Pipe()
	server, err := protocol.NewServerSession(c1)
	require.NoError(t, err)
	client, err := protocol.NewClientSession(c2)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	require.NoError(t, f.reg.RegisterHTTP("abc", &yamuxTunnel{id: "y", sess: server}))

	// The tunnel client answers only after it has seen the end of the
	// visitor's side.
	go func() {
		st, err := client.AcceptStream()
		if err != nil {
			return
		}
		defer st.Close()
		if _, err := protocol.ReadStreamHeader(st); err != nil {
			return
		}
		br := bufio.NewReader(st)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		if _, err := io.Copy(io.Discard, br); err != nil { // returns at the visitor's end of stream
			return
		}
		_, _ = st.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4\r\n\r\nlate"))
	}()

	v := f.visit()
	v.send(get("/"))
	require.NoError(t, v.c.CloseWrite())
	v.recvOK("late")
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// The idle timeout has to work when nobody waits on the stream: the visitor
// does not read, so the response copy is stuck in a write to the visitor.
func TestIdleTimeoutCoversAVisitorThatDoesNotRead(t *testing.T) {
	f := newFixture(t, Options{IdleTimeout: 400 * time.Millisecond})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send(get("/big"))
	b := sess.accept(t)
	b.next()

	// The backend sends until it cannot get rid of more: the visitor's
	// receive buffers are full and the edge is stuck writing to it.
	start := time.Now()
	chunk := make([]byte, 64<<10)
	var writeErr error
	for i := 0; i < 2048 && writeErr == nil; i++ { // at most 128 MiB
		_ = b.c.SetWriteDeadline(time.Now().Add(8 * time.Second))
		_, writeErr = b.c.Write(chunk)
	}
	require.Error(t, writeErr, "the edge took 128 MiB for a visitor that reads nothing")
	var ne net.Error
	require.False(t, errors.As(writeErr, &ne) && ne.Timeout(), "the stream to a visitor that does not read was left open")
	require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// Ending a connection must not need the tunnel client. With a real yamux
// stream, closing the edge's side neither ends the edge's own read nor does
// it close the visitor connection. After a refused request the edge waits
// for answers that the backend may still owe, but no longer than the idle
// timeout.
func TestRefusedFollowUpRequestEndsTheConnectionWithoutTheTunnelClient(t *testing.T) {
	f := newFixture(t, Options{IdleTimeout: 500 * time.Millisecond})

	c1, c2 := net.Pipe()
	server, err := protocol.NewServerSession(c1)
	require.NoError(t, err)
	client, err := protocol.NewClientSession(c2)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	require.NoError(t, f.reg.RegisterHTTP("abc", &yamuxTunnel{id: "y", sess: server}))

	// The tunnel client answers the first request and then neither sends nor closes.
	go func() {
		st, err := client.AcceptStream()
		if err != nil {
			return
		}
		if _, err := protocol.ReadStreamHeader(st); err != nil {
			return
		}
		if _, err := http.ReadRequest(bufio.NewReader(st)); err != nil {
			return
		}
		_, _ = st.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}()

	v := f.visit()
	v.send(get("/"))
	v.recvOK("ok")
	require.Equal(t, 1, f.edge.limiter.Total())

	// A request for another host. The tunnel client does not end the stream,
	// so only the edge itself can end this now, and it does when the idle
	// timeout has passed.
	start := time.Now() // before the last byte moves
	v.send("GET / HTTP/1.1\r\nHost: other.localhost\r\n\r\n")
	v.expectClosed(6*time.Second, "connection after a request for another host")
	require.GreaterOrEqual(t, time.Since(start), 350*time.Millisecond, "the edge waits for a pending answer")
	require.Eventually(t, func() bool { return f.edge.limiter.Visitors() == 0 }, 6*time.Second, 5*time.Millisecond,
		"the handler is still waiting for the tunnel client")
	// The stream the tunnel client keeps open holds its place in the total
	// until it is gone: here until the session ends.
	require.Equal(t, 1, f.edge.limiter.Total())
	require.NoError(t, server.Close())
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}
