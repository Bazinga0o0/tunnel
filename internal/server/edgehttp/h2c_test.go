package edgehttp

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// An upgrade to HTTP/2 over the same connection (h2c) is never passed on. A
// backend that accepted it would answer 101, the connection would become a
// raw copy, and the visitor's HTTP/2 requests would carry forwarding headers
// that the edge never sees.

const h2Settings = "HTTP2-Settings: AAMAAABkAAQAAP__\r\n"

func TestH2CUpgradeIsNeverPassedOn(t *testing.T) {
	for _, tc := range []struct {
		name           string
		headers        string
		wantConnection []string
	}{
		{"as a client sends it", "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n" + h2Settings, nil},
		{"other case", "Connection: UPGRADE, http2-settings\r\nUpgrade: H2C\r\nhttp2-settings: AAMAAABkAAQAAP__\r\n", nil},
		{"with keep-alive", "Connection: keep-alive, Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n" + h2Settings, []string{"keep-alive"}},
		{"with a version", "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c/2\r\n" + h2Settings, nil},
		{"twice", "Connection: Upgrade\r\nConnection: HTTP2-Settings\r\nUpgrade: h2c\r\nUpgrade: h2c\r\n" + h2Settings, nil},
		{"with empty tokens", "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c, ,\r\n" + h2Settings, nil},
		{"without its settings", "Connection: Upgrade\r\nUpgrade: h2c\r\n", nil},
		{"settings only", "Connection: HTTP2-Settings\r\n" + h2Settings, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, Options{})
			sess := f.tunnel("abc")
			v := f.visit()

			v.send(get("/h2c", forged, tc.headers) + get("/behind", forged))
			b := sess.accept(t)
			req := b.next()
			require.Equal(t, "/h2c", req.RequestURI)
			require.Empty(t, req.Header["Upgrade"], "the h2c upgrade is not passed on")
			require.Empty(t, req.Header["Http2-Settings"], "its settings are not passed on")
			require.Equal(t, tc.wantConnection, req.Header["Connection"])
			requireEdgeForwarding(t, req.Request, "abc.localhost")

			// The request is an ordinary one: the edge does not wait for the
			// backend before it forwards the next, and whatever the backend
			// answers, the connection stays HTTP.
			req = b.next()
			require.Equal(t, "/behind", req.RequestURI)
			requireEdgeForwarding(t, req.Request, "abc.localhost")
			b.write("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
			v.send(get("/after-101", forged))
			req = b.next()
			require.Equal(t, "/after-101", req.RequestURI)
			requireEdgeForwarding(t, req.Request, "abc.localhost")
		})
	}
}

// Other protocols named next to h2c keep working: only the h2c token goes.
func TestH2CTokenIsRemovedAndWebSocketKept(t *testing.T) {
	for _, tc := range []struct {
		name        string
		headers     string
		wantUpgrade []string
	}{
		{"h2c first", "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c, websocket\r\n" + h2Settings, []string{"websocket"}},
		{"h2c last", "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: websocket, H2C\r\n" + h2Settings, []string{"websocket"}},
		{"in lines of their own", "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nUpgrade: websocket\r\n" + h2Settings, []string{"websocket"}},
		{"between two others", "Connection: Upgrade\r\nUpgrade: websocket,h2c,  foo/2\r\n", []string{"websocket, foo/2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, Options{})
			sess := f.tunnel("abc")
			v := f.visit()

			frame := "\x81\x05hello"
			v.send(get("/ws", forged, tc.headers) + frame)
			b := sess.accept(t)
			req := b.next()
			require.Equal(t, tc.wantUpgrade, req.Header["Upgrade"])
			require.Equal(t, []string{"Upgrade"}, req.Header["Connection"])
			require.Empty(t, req.Header["Http2-Settings"])
			requireEdgeForwarding(t, req.Request, "abc.localhost")

			// It still asks to switch, and the backend's 101 still decides.
			b.expectSilent(200*time.Millisecond, "before the backend answered the upgrade request")
			b.write(switching)
			require.Equal(t, switching, v.readExactly(len(switching)))
			require.Equal(t, frame, b.readExactly(len(frame)))
		})
	}
}

// The requests that follow the first lose the h2c headers as well.
func TestH2CHeadersOnAFollowUpRequestAreRemoved(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send(get("/first"))
	b := sess.accept(t)
	b.next()
	b.reply("1")
	v.recvOK("1")

	v.send(get("/h2c", forged, "Connection: keep-alive, Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n"+h2Settings))
	req := b.next()
	require.Empty(t, req.Header["Upgrade"])
	require.Empty(t, req.Header["Http2-Settings"])
	require.Equal(t, []string{"keep-alive"}, req.Header["Connection"])
	requireEdgeForwarding(t, req.Request, "abc.localhost")
}

// HTTP/2 with prior knowledge, the other way to speak HTTP/2 without TLS:
// the client preface is not a request for a tunnel and is not forwarded.
func TestHTTP2PrefaceIsNotForwarded(t *testing.T) {
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	t.Run("first bytes of a connection", func(t *testing.T) {
		f := newFixture(t, Options{})
		sess := f.tunnel("abc")
		v := f.visit()
		v.send(preface)
		_ = v.c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, v.br) // an error answer, if any; the server may keep the connection
		require.Zero(t, sess.opens.Load(), "no stream is opened for an HTTP/2 preface")
	})

	t.Run("after a request", func(t *testing.T) {
		f := newFixture(t, Options{})
		sess := f.tunnel("abc")
		v := f.visit()
		v.send(get("/first"))
		b := sess.accept(t)
		b.next()
		b.reply("1")
		v.recvOK("1")

		v.send(preface + get("/smuggled", forged))
		b.expectEnd(6*time.Second, "stream after an HTTP/2 preface")
		v.expectClosed(6*time.Second, "connection after an HTTP/2 preface")
	})

	// With a Host header in its head the preface's request line names a
	// tunnel and reaches the edge as a request. What the backend receives is
	// then an HTTP/1.1 request with the edge's forwarding headers, never the
	// preface itself and never the HTTP/2 connection data behind it.
	withHost := "PRI * HTTP/2.0\r\nHost: abc.localhost\r\n" + forged + "\r\nSM\r\n\r\n"
	requireRewritten := func(t *testing.T, b *backend) {
		t.Helper()
		_ = b.c.SetReadDeadline(time.Now().Add(6 * time.Second))
		raw, err := io.ReadAll(b.br) // the edge refuses "SM" and ends the stream
		require.NoError(t, err, "the edge ends the stream after the preface's head")
		got := string(raw)
		require.NotContains(t, got, preface)
		require.NotContains(t, got, "HTTP/2.0")
		require.NotContains(t, got, "\r\nSM\r\n")
		line, _, _ := strings.Cut(got, "\r\n")
		require.Equal(t, "PRI * HTTP/1.1", line, "an HTTP/1.1 request line")
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(got)))
		require.NoError(t, err)
		requireEdgeForwarding(t, req, "abc.localhost")
	}

	t.Run("with a Host header, first bytes of a connection", func(t *testing.T) {
		f := newFixture(t, Options{})
		sess := f.tunnel("abc")
		v := f.visit()
		v.send(withHost)
		requireRewritten(t, sess.accept(t))
	})

	t.Run("with a Host header, after a request", func(t *testing.T) {
		f := newFixture(t, Options{})
		sess := f.tunnel("abc")
		v := f.visit()
		v.send(get("/first"))
		b := sess.accept(t)
		b.next()
		b.reply("1")
		v.recvOK("1")

		v.send(withHost)
		requireRewritten(t, b)
	})
}

// A Go HTTP server as the backend whose handler switches to "h2c" by hand
// when asked: it answers 101 and echoes what follows. (The standard library
// serves unencrypted HTTP/2 only with prior knowledge; the Upgrade mechanism
// needs golang.org/x/net/http2/h2c, which this module does not depend on.)
// Through the edge the handler is never asked.
func TestH2CUpgradeAgainstRealBackend(t *testing.T) {
	f := newFixture(t, Options{})
	rec := &record{}
	realTunnel(t, f, "abc", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r, "")
		if !strings.Contains(strings.ToLower(strings.Join(r.Header["Upgrade"], ",")), "h2c") {
			fmt.Fprint(w, "plain ", r.URL.Path)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw) // echo
	}))

	v := f.visit()
	v.send(get("/h2c", forged, "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n"+h2Settings) + get("/behind", forged))
	v.recvOK("plain /h2c")
	v.recvOK("plain /behind")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Len(t, rec.reqs, 2)
	for i, req := range rec.reqs {
		require.Empty(t, req.Header["Upgrade"], "request %d", i)
		require.Empty(t, req.Header["Http2-Settings"], "request %d", i)
		requireEdgeForwarding(t, req, "abc.localhost")
	}
}
