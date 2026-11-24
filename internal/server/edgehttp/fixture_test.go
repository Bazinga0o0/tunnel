package edgehttp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// scriptSession is a tunnel session whose OpenStream can be made to block,
// fail or panic. The backend end of every opened stream arrives on streams.
type scriptSession struct {
	id       string
	streams  chan protocol.Stream
	openHook func(n int32) error                   // n counts OpenStream calls from 1
	wrap     func(protocol.Stream) protocol.Stream // optional: replaces the edge's end of the stream
	opens    atomic.Int32
}

func (s *scriptSession) ID() string { return s.id }

func (s *scriptSession) OpenStream() (protocol.Stream, error) {
	n := s.opens.Add(1)
	if s.openHook != nil {
		if err := s.openHook(n); err != nil {
			return nil, err
		}
	}
	a, b := protocol.PipeStream()
	s.streams <- a
	if s.wrap != nil {
		b = s.wrap(b)
	}
	return b, nil
}

// fixture is an edge behind a real TLS server.
type fixture struct {
	t    *testing.T
	edge *Edge
	reg  *registry.Registry
	srv  *httptest.Server
	logs *logCapture
	// wrapHandler, when set before the first request, sits between the
	// server and the edge.
	wrapHandler func(http.Handler) http.Handler
}

func newFixture(t *testing.T, opts Options) *fixture {
	t.Helper()
	return newFixtureWith(t, opts, nil)
}

// newFixtureWith is newFixture with a hook that may change the settings of
// the http.Server before it starts.
func newFixtureWith(t *testing.T, opts Options, configure func(*http.Server)) *fixture {
	t.Helper()
	f := &fixture{t: t, logs: &logCapture{}}
	if opts.Domain == "" {
		opts.Domain = "localhost"
	}
	if opts.Registry == nil {
		opts.Registry = registry.New()
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(f.logs)
	}
	f.reg = opts.Registry
	f.edge = New(opts)
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var h http.Handler = f.edge
		if f.wrapHandler != nil {
			h = f.wrapHandler(h)
		}
		h.ServeHTTP(w, r)
	}))
	f.srv.Config.ErrorLog = slog.NewLogLogger(f.logs, slog.LevelError)
	if configure != nil {
		configure(f.srv.Config)
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// tunnel registers a tunnel for the subdomain.
func (f *fixture) tunnel(sub string) *scriptSession {
	f.t.Helper()
	s := &scriptSession{id: "session-" + sub, streams: make(chan protocol.Stream, 1024)}
	require.NoError(f.t, f.reg.RegisterHTTP(sub, s))
	return s
}

func (f *fixture) addr() string { return strings.TrimPrefix(f.srv.URL, "https://") }

// visitor is a raw TLS connection to the edge.
type visitor struct {
	t  *testing.T
	c  *tls.Conn
	br *bufio.Reader
}

func (f *fixture) visit() *visitor {
	f.t.Helper()
	d := &net.Dialer{Timeout: 10 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", f.addr(), &tls.Config{InsecureSkipVerify: true})
	require.NoError(f.t, err)
	f.t.Cleanup(func() { _ = c.Close() })
	return &visitor{t: f.t, c: c, br: bufio.NewReader(c)}
}

func (v *visitor) send(raw string) {
	v.t.Helper()
	_ = v.c.SetWriteDeadline(time.Now().Add(8 * time.Second))
	_, err := v.c.Write([]byte(raw))
	require.NoError(v.t, err)
}

// recv reads one response and its body.
func (v *visitor) recv() (*http.Response, string) {
	v.t.Helper()
	_ = v.c.SetReadDeadline(time.Now().Add(8 * time.Second))
	res, err := http.ReadResponse(v.br, nil)
	require.NoError(v.t, err)
	body, err := io.ReadAll(res.Body)
	require.NoError(v.t, err)
	return res, string(body)
}

// recvOK reads one response and requires status 200 with the given body.
func (v *visitor) recvOK(body string) {
	v.t.Helper()
	res, got := v.recv()
	require.Equal(v.t, 200, res.StatusCode)
	require.Equal(v.t, body, got)
}

// readExactly reads n raw bytes.
func (v *visitor) readExactly(n int) string {
	v.t.Helper()
	_ = v.c.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, n)
	_, err := io.ReadFull(v.br, buf)
	require.NoError(v.t, err)
	return string(buf)
}

// expectClosed asserts that the edge ends the connection within the given
// time without sending anything more.
func (v *visitor) expectClosed(within time.Duration, what string) {
	v.t.Helper()
	_ = v.c.SetReadDeadline(time.Now().Add(within))
	n, err := v.br.Read(make([]byte, 1))
	require.Zero(v.t, n, what)
	require.Error(v.t, err, what)
	var ne net.Error
	require.False(v.t, errors.As(err, &ne) && ne.Timeout(), "%s: still open after %v", what, within)
}

// expectOpen asserts that nothing arrives and the connection stays open for d.
func (v *visitor) expectOpen(d time.Duration, what string) {
	v.t.Helper()
	_ = v.c.SetReadDeadline(time.Now().Add(d))
	_, err := v.br.Peek(1)
	var ne net.Error
	require.True(v.t, errors.As(err, &ne) && ne.Timeout(), "%s: got %v", what, err)
}

// backend is the tunnel client's end of one stream.
type backend struct {
	t   *testing.T
	c   net.Conn
	br  *bufio.Reader
	hdr *protocol.StreamHeader
}

// accept waits for the next stream of the session and reads its header.
func (s *scriptSession) accept(t *testing.T) *backend {
	t.Helper()
	select {
	case st := <-s.streams:
		c := st.(net.Conn)
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
		hdr, err := protocol.ReadStreamHeader(c)
		require.NoError(t, err)
		return &backend{t: t, c: c, br: bufio.NewReader(c), hdr: hdr}
	case <-time.After(6 * time.Second):
		t.Fatal("no stream was opened towards the backend")
		return nil
	}
}

// seen is a request as the backend parsed it.
type seen struct {
	*http.Request
	Body string
}

// next reads one request the way a Go HTTP server would.
func (b *backend) next() *seen {
	b.t.Helper()
	req, err := http.ReadRequest(b.br)
	require.NoError(b.t, err)
	body, err := io.ReadAll(req.Body)
	require.NoError(b.t, err)
	return &seen{Request: req, Body: string(body)}
}

func (b *backend) write(raw string) {
	b.t.Helper()
	_, err := b.c.Write([]byte(raw))
	require.NoError(b.t, err)
}

// reply writes a keep-alive 200 response with the given body.
func (b *backend) reply(body string) {
	b.t.Helper()
	b.write("HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
}

func (b *backend) readExactly(n int) string {
	b.t.Helper()
	buf := make([]byte, n)
	_, err := io.ReadFull(b.br, buf)
	require.NoError(b.t, err)
	return string(buf)
}

// expectEnd asserts that the edge ends the stream without sending anything more.
func (b *backend) expectEnd(within time.Duration, what string) {
	b.t.Helper()
	_ = b.c.SetReadDeadline(time.Now().Add(within))
	p, err := b.br.Peek(1)
	require.Empty(b.t, p, "%s: the backend received more data", what)
	require.Error(b.t, err, what)
	var ne net.Error
	require.False(b.t, errors.As(err, &ne) && ne.Timeout(), "%s: stream still open after %v", what, within)
}

// requireEdgeForwarding asserts that the forwarding headers of a request are
// exactly the ones the edge derives from the connection, under every
// spelling a backend might accept.
func requireEdgeForwarding(t *testing.T, req *http.Request, wantHost string) {
	t.Helper()
	require.Equal(t, []string{"127.0.0.1"}, req.Header["X-Forwarded-For"], "X-Forwarded-For")
	require.Equal(t, []string{"https"}, req.Header["X-Forwarded-Proto"], "X-Forwarded-Proto")
	require.Equal(t, []string{wantHost}, req.Header["X-Forwarded-Host"], "X-Forwarded-Host")
	for key, values := range req.Header {
		switch norm := strings.ToLower(strings.ReplaceAll(key, "_", "-")); norm {
		case "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host":
			require.Contains(t, []string{"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"}, key,
				"header %q = %q from the visitor reached the backend", key, values)
		case "x-real-ip", "forwarded", "true-client-ip", "x-client-ip", "client-ip":
			t.Fatalf("header %q = %q from the visitor reached the backend", key, values)
		}
	}
}

// requestCount reads tunneld_request_total{type="http",status=status}.
func requestCount(t *testing.T, status string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != "tunneld_request_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["type"] == "http" && labels["status"] == status {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// logCapture is a slog.Handler that keeps every record.
type logCapture struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler       { return c }
func (c *logCapture) WithGroup(string) slog.Handler            { return c }
func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, r)
	return nil
}

func (c *logCapture) count(level slog.Level, msgPart string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range c.recs {
		if r.Level == level && strings.Contains(r.Message, msgPart) {
			n++
		}
	}
	return n
}
