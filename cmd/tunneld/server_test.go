package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
	"github.com/Bazinga0o0/tunnel/internal/server/edgehttp"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

// ---- the dispatcher's host handling ----

// recordingHandler counts the requests it gets.
type recordingHandler struct {
	mu    sync.Mutex
	hosts []string
}

func (h *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.hosts = append(h.hosts, r.Host)
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (h *recordingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.hosts)
}

func dispatch(t *testing.T, d http.Handler, host string) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = host
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)
	return w.Code
}

func TestDispatchHostSendsTheUIHostsToTheFrontend(t *testing.T) {
	for _, host := range []string{
		"tunnel.test", "app.tunnel.test", "APP.Tunnel.Test", "app.tunnel.test:443",
		"tunnel.test.", "app.tunnel.test.:8443", "TUNNEL.TEST:443",
	} {
		ui, tunnels := &recordingHandler{}, &recordingHandler{}
		d := dispatchHost("Tunnel.Test", ui, tunnels, nil, config.HTTPServer{})
		assert.Equal(t, http.StatusNoContent, dispatch(t, d, host), host)
		assert.Equal(t, 1, ui.count(), "%q goes to the frontend", host)
		assert.Zero(t, tunnels.count(), host)
	}
}

func TestDispatchHostSendsOtherHostsToTheTunnels(t *testing.T) {
	for _, host := range []string{"myapp.tunnel.test", "MyApp.Tunnel.Test.:443", "app2.tunnel.test", "other.example"} {
		ui, tunnels := &recordingHandler{}, &recordingHandler{}
		d := dispatchHost("tunnel.test", ui, tunnels, nil, config.HTTPServer{})
		assert.Equal(t, http.StatusNoContent, dispatch(t, d, host), host)
		assert.Zero(t, ui.count(), host)
		assert.Equal(t, 1, tunnels.count(), "%q goes to the tunnel edge", host)
	}
	// Without a frontend (static-token mode) the UI hosts go to the edge too.
	tunnels := &recordingHandler{}
	d := dispatchHost("tunnel.test", nil, tunnels, nil, config.HTTPServer{})
	dispatch(t, d, "app.tunnel.test")
	assert.Equal(t, 1, tunnels.count())
}

// A registered service wins over a tunnel of the same name: tunnels and
// reservations cannot take its subdomain, but one may have been reserved
// before the service was added.
func TestDispatchHostSendsServiceHostToService(t *testing.T) {
	reg := registry.New()
	// The edge finds this tunnel (and, with no connection to hijack, answers
	// 500); for an unknown name it answers 404.
	require.NoError(t, reg.RegisterHTTP("myservice", refusingSession{}))
	logger, _ := captureLog()
	edge := edgehttp.New(edgehttp.Options{Domain: "tunnel.test", Registry: reg, Logger: logger})
	ui, svc := &recordingHandler{}, &recordingHandler{}
	d := dispatchHost("Tunnel.Test", ui, edge, map[string]http.Handler{"myservice.tunnel.test": svc}, config.HTTPServer{})

	for _, host := range []string{"myservice.tunnel.test", "MyService.Tunnel.Test.:443"} {
		assert.Equal(t, http.StatusNoContent, dispatch(t, d, host), host)
	}
	assert.Equal(t, 2, svc.count(), "the service host goes to the service, not to the tunnel of that name")
	assert.Equal(t, http.StatusNotFound, dispatch(t, d, "other.tunnel.test"), "other names stay with the tunnel edge")
	assert.Equal(t, 2, svc.count())
	assert.Zero(t, ui.count())
}

func TestDispatchHostRefusesInvalidHosts(t *testing.T) {
	for _, host := range []string{
		"", "bad_host.tunnel.test", "app.tunnel.test:99999", "app.tunnel.test:abc", "[::1]", "127.0.0.1",
		"app..tunnel.test", "app.tunnel.test:443:443", "app tunnel.test", "app.tunnel.test/x",
	} {
		ui, tunnels := &recordingHandler{}, &recordingHandler{}
		d := dispatchHost("tunnel.test", ui, tunnels, nil, config.HTTPServer{})
		assert.Equal(t, http.StatusBadRequest, dispatch(t, d, host), "%q", host)
		assert.Zero(t, ui.count()+tunnels.count(), "%q reaches no handler", host)
	}
}

// ---- settings of the public HTTPS server ----

// net/http logs one line per failed TLS handshake; the server passes them on
// through a limiter.
func TestPublicServerErrorLogIsRateLimited(t *testing.T) {
	logger, logs := captureLog()
	srv := newPublicServer(http.NotFoundHandler(), config.HTTPServer{}, logger)
	require.NotNil(t, srv.ErrorLog)
	for i := 0; i < 50; i++ {
		srv.ErrorLog.Printf("http: TLS handshake error from 192.0.2.%d:4711: EOF", i)
	}
	assert.Equal(t, 1, strings.Count(logs.String(), "TLS handshake error"), logs.String())
	assert.Contains(t, logs.String(), "level=WARN")

	// Handshake noise does not swallow a panic and its stack.
	srv.ErrorLog.Printf("http: panic serving 192.0.2.7:4711: boom\ngoroutine 1 [running]:\nmain.handler()")
	assert.Contains(t, logs.String(), "panic serving 192.0.2.7:4711: boom")
	assert.Contains(t, logs.String(), "level=ERROR")
}

func TestPublicServerDefaults(t *testing.T) {
	logger, _ := captureLog()
	srv := newPublicServer(http.NotFoundHandler(), config.HTTPServer{}, logger)
	assert.Equal(t, 10*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 120*time.Second, srv.IdleTimeout)
	assert.Equal(t, 64<<10, srv.MaxHeaderBytes)
	assert.Zero(t, srv.ReadTimeout, "tunnel requests are hijacked: no timeout for the whole connection")
	assert.Zero(t, srv.WriteTimeout, "tunnel requests are hijacked: no timeout for the whole connection")

	srv = newPublicServer(http.NotFoundHandler(), config.HTTPServer{ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 4 * time.Second, MaxHeaderBytes: 8192}, logger)
	assert.Equal(t, 3*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 4*time.Second, srv.IdleTimeout)
	assert.Equal(t, 8192, srv.MaxHeaderBytes)
}

// publicServer runs the public HTTPS server on a loopback port with the
// given handlers and settings, the way serve does.
func publicServer(t *testing.T, ui, tunnels http.Handler, s config.HTTPServer) string {
	t.Helper()
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"tunnel.test", "*.tunnel.test"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	logger, _ := captureLog()
	ln, err := listenPublic(testports.Loopback+":0", &tls.Config{Certificates: []tls.Certificate{cert}}, s, logger)
	require.NoError(t, err)
	srv := newPublicServer(dispatchHost("tunnel.test", ui, tunnels, nil, s), s, logger)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
	return ln.Addr().String()
}

func dialTLS(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// closedWithin waits until the server closes conn and returns how long that
// took.
func closedWithin(t *testing.T, conn net.Conn, limit time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(limit)))
	buf := make([]byte, 4096)
	for {
		_, err := conn.Read(buf)
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("connection still open after %s", limit)
		}
		return time.Since(start)
	}
}

func TestSlowRequestHeadIsCutAfterReadHeaderTimeout(t *testing.T) {
	addr := publicServer(t, &recordingHandler{}, &recordingHandler{}, config.HTTPServer{ReadHeaderTimeout: 300 * time.Millisecond})
	conn := dialTLS(t, addr)
	_, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: app.tunnel.test\r\n"))
	require.NoError(t, err)
	took := closedWithin(t, conn, waitFor)
	assert.GreaterOrEqual(t, took, 200*time.Millisecond)
}

func TestSilentClientIsCutDuringTheTLSHandshake(t *testing.T) {
	addr := publicServer(t, &recordingHandler{}, &recordingHandler{}, config.HTTPServer{ReadHeaderTimeout: 300 * time.Millisecond})
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	closedWithin(t, conn, waitFor)
}

func TestOversizedRequestHeadIsRefused(t *testing.T) {
	ui := &recordingHandler{}
	addr := publicServer(t, ui, &recordingHandler{}, config.HTTPServer{MaxHeaderBytes: 4096})
	conn := dialTLS(t, addr)
	req := "GET / HTTP/1.1\r\nHost: app.tunnel.test\r\nX-Big: " + strings.Repeat("a", 16<<10) + "\r\n\r\n"
	_, _ = conn.Write([]byte(req))
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusRequestHeaderFieldsTooLarge, res.StatusCode)
	assert.Zero(t, ui.count())
}

// bodyReader reads the request body and reports the outcome.
type bodyReader struct {
	result chan error
}

func (b *bodyReader) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, err := io.ReadAll(r.Body)
	b.result <- err
	w.WriteHeader(http.StatusNoContent)
}

func TestFrontendRequestsHaveAReadDeadline(t *testing.T) {
	ui := &bodyReader{result: make(chan error, 1)}
	addr := publicServer(t, ui, &recordingHandler{}, config.HTTPServer{FrontendReadTimeout: 300 * time.Millisecond})
	conn := dialTLS(t, addr)
	_, err := conn.Write([]byte("POST /login HTTP/1.1\r\nHost: app.tunnel.test\r\nContent-Length: 100\r\n\r\nonly-ten-b"))
	require.NoError(t, err)
	select {
	case err := <-ui.result:
		require.Error(t, err, "the body read ends at the deadline")
	case <-time.After(waitFor):
		t.Fatal("the frontend handler is still reading")
	}
}

func TestFrontendRequestsHaveAWriteDeadline(t *testing.T) {
	result := make(chan error, 1)
	ui := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 64<<10)
		var err error
		for i := 0; i < 4096 && err == nil; i++ { // up to 256 MiB, far beyond the socket buffers
			_, err = w.Write(chunk)
		}
		result <- err
	})
	addr := publicServer(t, ui, &recordingHandler{}, config.HTTPServer{FrontendWriteTimeout: 300 * time.Millisecond})
	conn := dialTLS(t, addr)
	_, err := conn.Write([]byte("GET /big HTTP/1.1\r\nHost: app.tunnel.test\r\n\r\n"))
	require.NoError(t, err)
	// The client reads nothing.
	select {
	case err := <-result:
		require.Error(t, err, "the response write ends at the deadline")
	case <-time.After(waitFor):
		t.Fatal("the frontend handler is still writing")
	}
}

// The read deadline bounds reading the request, not the handler's work after
// it: net/http cancels the request context when a read fails, and its
// background read after the body would otherwise trip over the deadline.
func TestFrontendReadDeadlineEndsWithTheBody(t *testing.T) {
	result := make(chan error, 1)
	ui := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			result <- err
			return
		}
		select { // work for three times the read timeout
		case <-r.Context().Done():
			result <- r.Context().Err()
		case <-time.After(600 * time.Millisecond):
			result <- nil
		}
		w.WriteHeader(http.StatusNoContent)
	})
	addr := publicServer(t, ui, &recordingHandler{}, config.HTTPServer{FrontendReadTimeout: 200 * time.Millisecond})
	conn := dialTLS(t, addr)
	br := bufio.NewReader(conn)
	for _, req := range []string{
		"POST /tokens HTTP/1.1\r\nHost: app.tunnel.test\r\nContent-Length: 5\r\n\r\nhello",
		"GET /dashboard HTTP/1.1\r\nHost: app.tunnel.test\r\n\r\n",
	} {
		_, err := conn.Write([]byte(req))
		require.NoError(t, err)
		select {
		case err := <-result:
			require.NoError(t, err, "the request context was cancelled: %q", req)
		case <-time.After(waitFor):
			t.Fatal("the handler did not finish")
		}
		res, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		_ = res.Body.Close()
		assert.Equal(t, http.StatusNoContent, res.StatusCode)
	}
}

func TestTunnelRequestsHaveNoDeadline(t *testing.T) {
	tunnels := &bodyReader{result: make(chan error, 1)}
	s := config.HTTPServer{FrontendReadTimeout: 200 * time.Millisecond, FrontendWriteTimeout: 200 * time.Millisecond}
	addr := publicServer(t, &recordingHandler{}, tunnels, s)
	conn := dialTLS(t, addr)
	br := bufio.NewReader(conn)

	// A frontend request first, so that its deadlines are set on the
	// connection ...
	_, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: app.tunnel.test\r\n\r\n"))
	require.NoError(t, err)
	res, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Equal(t, http.StatusNoContent, res.StatusCode)

	// ... then a tunnel request on the same connection that takes longer
	// than both of them.
	time.Sleep(400 * time.Millisecond)
	_, err = conn.Write([]byte("POST / HTTP/1.1\r\nHost: myapp.tunnel.test\r\nContent-Length: 20\r\n\r\nfirst-ten-"))
	require.NoError(t, err)
	time.Sleep(400 * time.Millisecond)
	_, err = conn.Write([]byte("last--ten-"))
	require.NoError(t, err)
	select {
	case err := <-tunnels.result:
		require.NoError(t, err, "the tunnel request is not cut")
	case <-time.After(waitFor):
		t.Fatal("the tunnel handler got no body")
	}
	res, err = http.ReadResponse(br, nil)
	require.NoError(t, err, "the response is written although the earlier write deadline has passed")
	_ = res.Body.Close()
	assert.Equal(t, http.StatusNoContent, res.StatusCode)
}

// ---- answers on the tunnel path end the connection ----

// refusingSession is a registered HTTP tunnel whose client cannot take a
// stream: the edge answers 502 without hijacking the connection.
type refusingSession struct{}

func (refusingSession) ID() string { return "refusing" }
func (refusingSession) OpenStream() (protocol.Stream, error) {
	return nil, errors.New("session shutdown")
}

// A request on the tunnel path that announces a body and does not send it
// gets its answer, and the connection is closed within the header timeout.
// Before, net/http waited for the body without any deadline: one source
// address could hold its slots on the public listener for nothing.
func TestTunnelPathAnswersCloseTheConnection(t *testing.T) {
	const headerTimeout = 2 * time.Second
	reg := registry.New()
	require.NoError(t, reg.RegisterHTTP("refuses", refusingSession{}))
	logger, _ := captureLog()
	edge := edgehttp.New(edgehttp.Options{Domain: "tunnel.test", Registry: reg, Logger: logger})
	addr := publicServer(t, &recordingHandler{}, edge, config.HTTPServer{ReadHeaderTimeout: headerTimeout})

	for _, c := range []struct {
		host   string
		status int
	}{
		{"nosuch.tunnel.test", http.StatusNotFound},     // unknown tunnel (edge)
		{"bad_host.tunnel.test", http.StatusBadRequest}, // invalid host (dispatcher)
		{"refuses.tunnel.test", http.StatusBadGateway},  // known tunnel, stream refused (edge)
	} {
		for _, framing := range []string{"Content-Length: 100\r\n", "Transfer-Encoding: chunked\r\n", ""} {
			conn := dialTLS(t, addr)
			_, err := conn.Write([]byte("POST /upload HTTP/1.1\r\nHost: " + c.host + "\r\n" + framing + "\r\n"))
			require.NoError(t, err)
			start := time.Now()
			require.NoError(t, conn.SetReadDeadline(start.Add(headerTimeout)))
			res, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err, "%s %q: no answer", c.host, framing)
			_ = res.Body.Close()
			assert.Equal(t, c.status, res.StatusCode, "%s %q", c.host, framing)
			assert.True(t, res.Close, "%s %q: the answer must say Connection: close", c.host, framing)
			closedWithin(t, conn, headerTimeout-time.Since(start))
		}
	}
}

// The web UI keeps keep-alive, also after an error answer, and its own
// deadlines (see the frontend deadline tests above).
func TestFrontendAnswersKeepTheConnection(t *testing.T) {
	ui := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	addr := publicServer(t, ui, &recordingHandler{}, config.HTTPServer{ReadHeaderTimeout: 2 * time.Second})
	conn := dialTLS(t, addr)
	br := bufio.NewReader(conn)
	for _, c := range []struct {
		req    string
		status int
	}{
		{"GET /missing HTTP/1.1\r\nHost: app.tunnel.test\r\n\r\n", http.StatusNotFound},
		{"POST /form HTTP/1.1\r\nHost: tunnel.test\r\nContent-Length: 5\r\n\r\nhello", http.StatusNoContent},
		{"GET / HTTP/1.1\r\nHost: app.tunnel.test\r\n\r\n", http.StatusNoContent},
	} {
		_, err := conn.Write([]byte(c.req))
		require.NoError(t, err)
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(waitFor)))
		res, err := http.ReadResponse(br, nil)
		require.NoError(t, err, "the connection was closed before %q", c.req)
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		assert.Equal(t, c.status, res.StatusCode)
		assert.False(t, res.Close, "a web UI answer keeps the connection: %q", c.req)
	}
}

// ---- connection limits of the public listener ----

// requireRefusedBeforeHandshake proves that the server closes a new
// connection before its TLS handshake. An accepted connection would complete
// the handshake: the server's handshake timeout (10 s by default) is far
// longer than the client's wait here, so it cannot be what ends the attempt.
func requireRefusedBeforeHandshake(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, tc.SetDeadline(time.Now().Add(5*time.Second)))
	err = tc.Handshake()
	require.Error(t, err, "the connection over the limit completed its TLS handshake")
	var ne net.Error
	require.False(t, errors.As(err, &ne) && ne.Timeout(), "the connection was left waiting instead of closed: %v", err)
}

func TestPublicListenerLimitsConnectionsPerSource(t *testing.T) {
	addr := publicServer(t, &recordingHandler{}, &recordingHandler{}, config.HTTPServer{MaxConnsPerIP: 2, MaxConns: -1})
	first := dialTLS(t, addr)
	second := dialTLS(t, addr)
	_ = second

	// The third connection from the same address is closed at once.
	requireRefusedBeforeHandshake(t, addr)

	// A closed connection gives its slot back.
	require.NoError(t, first.Close())
	require.Eventually(t, func() bool {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return false
		}
		defer c.Close()
		_, err = fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: app.tunnel.test\r\n\r\n")
		if err != nil {
			return false
		}
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return false
		}
		_ = res.Body.Close()
		return res.StatusCode == http.StatusNoContent
	}, waitFor, 50*time.Millisecond)
}

func TestPublicListenerLimitsConnectionsInTotal(t *testing.T) {
	addr := publicServer(t, &recordingHandler{}, &recordingHandler{}, config.HTTPServer{MaxConns: 1, MaxConnsPerIP: -1})
	dialTLS(t, addr)
	requireRefusedBeforeHandshake(t, addr)
}

// With both limits disabled nothing is refused.
func TestPublicListenerWithoutLimits(t *testing.T) {
	addr := publicServer(t, &recordingHandler{}, &recordingHandler{}, config.HTTPServer{MaxConns: -1, MaxConnsPerIP: -1})
	for i := 0; i < 5; i++ {
		dialTLS(t, addr)
	}
}

func TestPublicListenerDefaultLimits(t *testing.T) {
	assert.Equal(t, 1100, config.HTTPServer{}.Resolved().MaxConns)
	assert.Equal(t, 128, config.HTTPServer{}.Resolved().MaxConnsPerIP)

	inner, err := net.Listen("tcp", testports.Loopback+":0")
	require.NoError(t, err)
	defer inner.Close()
	logger, _ := captureLog()
	ln := limitPublicListener(inner, config.HTTPServer{}, logger)
	limited, ok := ln.(*limitListener)
	require.True(t, ok, "the defaults limit the listener")

	// The limiter Accept uses enforces 128 per source and 1100 in total.
	var releases []func()
	defer func() {
		for _, r := range releases {
			r()
		}
	}()
	take := func(source string) error {
		release, err := limited.limiter.Acquire("", edgeguard.ParseSource(source))
		if err == nil {
			releases = append(releases, release)
		}
		return err
	}
	for i := 0; i < 128; i++ {
		require.NoError(t, take("192.0.2.1:1000"))
	}
	require.ErrorIs(t, take("192.0.2.1:1000"), edgeguard.ErrLimitSource, "the 129th connection from one address")
	for i := 128; i < 1100; i++ {
		require.NoError(t, take(fmt.Sprintf("10.%d.%d.1:1000", i/256, i%256)))
	}
	require.ErrorIs(t, take("198.51.100.1:1000"), edgeguard.ErrLimitTotal, "the 1101st connection")

	ln = limitPublicListener(inner, config.HTTPServer{MaxConns: -1, MaxConnsPerIP: -1}, logger)
	assert.Same(t, inner, ln, "both limits disabled: the listener is used as it is")
}
