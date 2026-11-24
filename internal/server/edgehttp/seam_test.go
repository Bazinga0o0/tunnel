package edgehttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/client/connector"
	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// These tests run the edge against the real counterparts on both seams: a
// yamux session with the tunnel client's connector behind it, and a Go HTTP
// server as the backend.

// yamuxTunnel is a registry session on top of a real yamux session.
type yamuxTunnel struct {
	id    string
	sess  protocol.Session
	opens atomic.Int32
}

func (y *yamuxTunnel) ID() string { return y.id }

func (y *yamuxTunnel) OpenStream() (protocol.Stream, error) {
	y.opens.Add(1)
	return y.sess.OpenStream()
}

// realTunnel registers a tunnel for sub whose streams the client connector
// forwards to the given backend.
func realTunnel(t *testing.T, f *fixture, sub string, backend http.Handler) *yamuxTunnel {
	t.Helper()
	srv := httptest.NewServer(backend)
	t.Cleanup(srv.Close)

	c1, c2 := net.Pipe()
	server, err := protocol.NewServerSession(c1)
	require.NoError(t, err)
	client, err := protocol.NewClientSession(c2)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	conn := connector.New(connector.Options{LocalAddr: strings.TrimPrefix(srv.URL, "http://"), ExpectedType: protocol.StreamTypeHTTP})
	go func() {
		for {
			stream, err := client.AcceptStream()
			if err != nil {
				return
			}
			go func() { _ = conn.Handle(stream) }()
		}
	}()

	tun := &yamuxTunnel{id: "yamux-" + sub, sess: server}
	require.NoError(t, f.reg.RegisterHTTP(sub, tun))
	return tun
}

// record keeps what the backend saw of each request.
type record struct {
	mu   sync.Mutex
	reqs []*http.Request
	body []string
}

func (r *record) add(req *http.Request, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req)
	r.body = append(r.body, body)
}

func TestKeepAliveClientAgainstRealBackend(t *testing.T) {
	f := newFixture(t, Options{})
	rec := &record{}
	tun := realTunnel(t, f, "abc", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.add(r, string(body))
		fmt.Fprintf(w, "%s %s (%d bytes)", r.Method, r.URL.Path, len(body))
	}))

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			ExpectContinueTimeout: 5 * time.Second,
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return tls.Dial("tcp", f.addr(), &tls.Config{InsecureSkipVerify: true})
			},
		},
	}
	do := func(method, path string, body io.Reader, header map[string]string) string {
		req, err := http.NewRequest(method, "https://abc.localhost"+path, body)
		require.NoError(t, err)
		req.Header.Set("X-Forwarded-For", "6.6.6.6")
		req.Header.Set("X-Real-IP", "6.6.6.6")
		req.Header.Set("Forwarded", "for=6.6.6.6")
		for k, v := range header {
			req.Header.Set(k, v)
		}
		res, err := client.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		got, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, 200, res.StatusCode)
		return string(got)
	}

	require.Equal(t, "GET /one (0 bytes)", do("GET", "/one", nil, nil))
	require.Equal(t, "POST /two (5 bytes)", do("POST", "/two", strings.NewReader("hello"), nil))
	// A reader of unknown length makes the client send a chunked body.
	require.Equal(t, "PUT /three (70000 bytes)", do("PUT", "/three", io.MultiReader(bytes.NewReader(bytes.Repeat([]byte("c"), 70000))), nil))
	require.Equal(t, "POST /four (4 bytes)", do("POST", "/four", strings.NewReader("wait"), map[string]string{"Expect": "100-continue"}))
	require.Equal(t, "GET /five (0 bytes)", do("GET", "/five", nil, nil))

	require.EqualValues(t, 1, tun.opens.Load(), "the client reused one connection, so the edge used one stream")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Len(t, rec.reqs, 5)
	for i, req := range rec.reqs {
		require.Equal(t, "abc.localhost", req.Host, "request %d", i)
		requireEdgeForwarding(t, req, "abc.localhost")
	}
	require.Equal(t, []string{"chunked"}, rec.reqs[2].TransferEncoding)
	require.Equal(t, strings.Repeat("c", 70000), rec.body[2])
}

func TestUpgradeAgainstRealBackend(t *testing.T) {
	f := newFixture(t, Options{})
	var upgradeReq atomic.Pointer[http.Request]
	realTunnel(t, f, "abc", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "echo" {
			fmt.Fprint(w, "plain")
			return
		}
		upgradeReq.Store(r)
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw) // echo
	}))

	// The upgrade is the first request of its connection: the backend
	// answers 101 and both directions carry raw bytes from then on.
	v := f.visit()
	v.send(get("/echo", forged, "Connection: Upgrade\r\n", "Upgrade: echo\r\n"))
	res, _ := v.recv()
	require.Equal(t, 101, res.StatusCode)
	requireEdgeForwarding(t, upgradeReq.Load(), "abc.localhost")

	for _, msg := range []string{"ping", "\x00\x01\x02 binary \xff", "GET / HTTP/1.1\r\n\r\n"} {
		v.send(msg)
		require.Equal(t, msg, v.readExactly(len(msg)))
	}

	// On a connection that has carried a request before, the upgrade does
	// not reach the backend: the request is answered like any other.
	later := f.visit()
	later.send(get("/plain"))
	later.recvOK("plain")
	later.send(get("/echo", forged, "Connection: Upgrade\r\n", "Upgrade: echo\r\n"))
	later.recvOK("plain")
	later.send(get("/plain", forged))
	later.recvOK("plain")
}

// The idle timeout must not depend on the tunnel client: a yamux stream
// keeps serving reads after the edge closed its side.
func TestIdleTimeoutAgainstSilentTunnelClient(t *testing.T) {
	f := newFixture(t, Options{IdleTimeout: 800 * time.Millisecond})

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

	// The tunnel client answers one request and then neither sends nor closes.
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

	v.expectClosed(6*time.Second, "idle visitor connection")
	require.Eventually(t, func() bool { return f.edge.limiter.Visitors() == 0 }, 6*time.Second, 5*time.Millisecond,
		"the handler is still waiting for the tunnel client")
	// The stream the tunnel client keeps open holds its place in the total
	// until it is gone: here until the session ends.
	require.Equal(t, 1, f.edge.limiter.Total())
	require.NoError(t, server.Close())
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}
