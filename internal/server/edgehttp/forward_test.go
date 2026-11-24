package edgehttp

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// forged is a set of forwarding headers as a visitor might send them.
const forged = "X-Forwarded-For: 6.6.6.6\r\n" +
	"X-Real-IP: 6.6.6.6\r\n" +
	"Forwarded: for=6.6.6.6;proto=http;host=evil.example\r\n" +
	"X-Forwarded-Proto: http\r\n" +
	"X-Forwarded-Host: evil.example\r\n"

// get builds a GET request for abc.localhost with extra header lines.
func get(path string, headerLines ...string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: abc.localhost\r\n" + strings.Join(headerLines, "") + "\r\n"
}

// --- forwarding headers -----------------------------------------------------------

func TestFirstRequestGetsForwardingHeadersFromTheConnection(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")

	v := f.visit()
	v.send(get("/path?x=1&y=%2F", forged, "X-Custom: keep me\r\n", "Cookie: a=b\r\n", "User-Agent: test-agent/1.0\r\n"))

	b := sess.accept(t)
	require.Equal(t, protocol.StreamTypeHTTP, b.hdr.StreamType)
	require.Equal(t, "abc.localhost", b.hdr.OriginalHost)
	require.Equal(t, "127.0.0.1", b.hdr.RemoteIP)
	require.Equal(t, "https", b.hdr.Scheme)

	req := b.next()
	require.Equal(t, "GET", req.Method)
	require.Equal(t, "/path?x=1&y=%2F", req.RequestURI)
	require.Equal(t, "abc.localhost", req.Host)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	require.Equal(t, "keep me", req.Header.Get("X-Custom"))
	require.Equal(t, "a=b", req.Header.Get("Cookie"))
	require.Equal(t, "test-agent/1.0", req.Header.Get("User-Agent"))

	b.reply("ok")
	v.recvOK("ok")
}

func TestEveryRequestOfAKeepAliveConnectionGetsForwardingHeaders(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	before := requestCount(t, "proxied")
	v.send(get("/one"))
	b := sess.accept(t)
	req := b.next()
	require.Equal(t, "/one", req.RequestURI)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	b.reply("1")
	v.recvOK("1")

	// The follow-up requests carry forged headers. They must not reach the
	// backend as raw bytes.
	v.send(get("/two", forged))
	req = b.next()
	require.Equal(t, "/two", req.RequestURI)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	b.reply("2")
	v.recvOK("2")

	v.send("POST /three HTTP/1.1\r\nHost: ABC.Localhost.:443\r\n" + forged + "Content-Length: 4\r\n\r\nbody")
	req = b.next()
	require.Equal(t, "POST", req.Method)
	require.Equal(t, "/three", req.RequestURI)
	require.Equal(t, "body", req.Body)
	require.Equal(t, "ABC.Localhost.:443", req.Host, "the Host header is passed on as sent")
	requireEdgeForwarding(t, req.Request, "abc.localhost") // normalised; 443 is the default port of https
	b.reply("3")
	v.recvOK("3")

	require.EqualValues(t, 1, sess.opens.Load(), "keep-alive: all three requests used one connection and one stream")
	// The edge counts a request after its write to the backend returns,
	// which can be just after the backend has already answered it.
	require.Eventually(t, func() bool { return requestCount(t, "proxied") == before+3 },
		2*time.Second, 5*time.Millisecond, "every forwarded request is counted")
}

func TestPipelinedRequestsAreAllRewritten(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	// Three requests in a single write, the middle one with a body.
	v.send(get("/p1", forged) +
		"POST /p2 HTTP/1.1\r\nHost: abc.localhost\r\n" + forged + "Content-Length: 5\r\n\r\nhello" +
		get("/p3", forged))

	b := sess.accept(t)
	for i, want := range []string{"/p1", "/p2", "/p3"} {
		req := b.next()
		require.Equal(t, want, req.RequestURI)
		requireEdgeForwarding(t, req.Request, "abc.localhost")
		if i == 1 {
			require.Equal(t, "hello", req.Body)
		}
		b.reply(want)
	}
	v.recvOK("/p1")
	v.recvOK("/p2")
	v.recvOK("/p3")
}

func TestRequestArrivingByteByByteIsRewritten(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send(get("/first"))
	b := sess.accept(t)
	b.next()
	b.reply("1")
	v.recvOK("1")

	raw := "POST /slow HTTP/1.1\r\nHost: abc.localhost\r\n" + forged + "Content-Length: 3\r\n\r\nxyz"
	go func() {
		for i := 0; i < len(raw); i++ {
			if _, err := v.c.Write([]byte{raw[i]}); err != nil {
				return
			}
		}
	}()
	req := b.next()
	require.Equal(t, "/slow", req.RequestURI)
	require.Equal(t, "xyz", req.Body)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	b.reply("2")
	v.recvOK("2")
}

func TestForwardingHeadersAreRemovedUnderEverySpelling(t *testing.T) {
	spellings := map[string]string{
		"lower case":          "x-forwarded-for: 1.1.1.1\r\nx-real-ip: 1.1.1.1\r\nforwarded: for=1.1.1.1\r\nx-forwarded-proto: http\r\nx-forwarded-host: evil\r\n",
		"upper case":          "X-FORWARDED-FOR: 1.1.1.1\r\nX-REAL-IP: 1.1.1.1\r\nFORWARDED: for=1.1.1.1\r\nX-FORWARDED-PROTO: http\r\nX-FORWARDED-HOST: evil\r\n",
		"repeated lines":      "X-Forwarded-For: 1.1.1.1\r\nX-Forwarded-For: 2.2.2.2\r\nx-forwarded-for: 3.3.3.3\r\n",
		"underscores":         "X_Forwarded_For: 1.1.1.1\r\nX_Real_IP: 1.1.1.1\r\nX_Forwarded_Proto: http\r\nX_Forwarded_Host: evil\r\n",
		"underscores, mixed":  "x_forwarded-for: 1.1.1.1\r\nX-REAL_ip: 1.1.1.1\r\nx-FORWARDED_host: evil\r\n",
		"folded continuation": "X-Forwarded-For: 1.1.1.1\r\n 2.2.2.2\r\nX-Real-IP:\r\n\t1.1.1.1\r\n",
		"empty values":        "X-Forwarded-For:\r\nX-Real-IP:\r\nForwarded:\r\n",
		// Client addresses under the names that chi's RealIP (True-Client-IP
		// first), Rails (Client-IP) and others read.
		"client address headers":             "True-Client-IP: 1.1.1.1\r\nX-Client-IP: 1.1.1.1\r\nClient-IP: 1.1.1.1\r\n",
		"client address headers, cases":      "TRUE-CLIENT-IP: 1.1.1.1\r\nx-client-ip: 1.1.1.1\r\nclient-ip: 1.1.1.1\r\n",
		"client address headers, underscore": "True_Client_IP: 1.1.1.1\r\nX_Client_Ip: 1.1.1.1\r\nCLIENT_IP: 1.1.1.1\r\ntrue-client_ip: 2.2.2.2\r\n",
	}
	for name, lines := range spellings {
		for _, position := range []string{"first request", "follow-up request"} {
			t.Run(name+", "+position, func(t *testing.T) {
				f := newFixture(t, Options{})
				sess := f.tunnel("abc")
				v := f.visit()

				var b *backend
				if position == "follow-up request" {
					v.send(get("/benign"))
					b = sess.accept(t)
					b.next()
					b.reply("ok")
					v.recvOK("ok")
				}
				v.send(get("/probe", lines, "X-Other: stays\r\n"))
				if b == nil {
					b = sess.accept(t)
				}
				req := b.next()
				require.Equal(t, "/probe", req.RequestURI)
				requireEdgeForwarding(t, req.Request, "abc.localhost")
				require.Equal(t, "stays", req.Header.Get("X-Other"))
				b.reply("ok")
				v.recvOK("ok")
			})
		}
	}
}

func TestUserAgentIsPassedOnUnchanged(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	// No User-Agent from the visitor: none is invented, on any request.
	v.send(get("/one"))
	b := sess.accept(t)
	req := b.next()
	require.NotContains(t, req.Header, "User-Agent")
	b.reply("1")
	v.recvOK("1")

	v.send(get("/two"))
	req = b.next()
	require.NotContains(t, req.Header, "User-Agent")
	b.reply("2")
	v.recvOK("2")

	v.send(get("/three", "User-Agent: curl/8.0\r\n"))
	req = b.next()
	require.Equal(t, []string{"curl/8.0"}, req.Header["User-Agent"])
	b.reply("3")
	v.recvOK("3")
}

// A visitor can also send fields as trailers of a chunked body. A backend
// that merges trailers into the headers must not find forwarding fields
// there.
func TestForwardingHeadersCannotArriveAsTrailers(t *testing.T) {
	for _, position := range []string{"first request", "follow-up request"} {
		t.Run(position, func(t *testing.T) {
			f := newFixture(t, Options{})
			sess := f.tunnel("abc")
			v := f.visit()

			var b *backend
			if position == "follow-up request" {
				v.send(get("/benign"))
				b = sess.accept(t)
				b.next()
				b.reply("ok")
				v.recvOK("ok")
			}
			v.send("POST /t HTTP/1.1\r\nHost: abc.localhost\r\nTransfer-Encoding: chunked\r\n" +
				"Trailer: X-Forwarded-For, X-Checksum, x_real_ip\r\n\r\n" +
				"5\r\nhello\r\n0\r\n" +
				"X-Forwarded-For: 6.6.6.6\r\nx_real_ip: 6.6.6.6\r\nForwarded: for=6.6.6.6\r\nX-Forwarded-Host: evil\r\nX-Checksum: sum\r\n\r\n")
			if b == nil {
				b = sess.accept(t)
			}
			req := b.next()
			require.Equal(t, "hello", req.Body)
			requireEdgeForwarding(t, req.Request, "abc.localhost")
			require.Equal(t, http.Header{"X-Checksum": {"sum"}}, req.Trailer,
				"only the trailer that is not a forwarding field reaches the backend")
			b.reply("ok")
			v.recvOK("ok")
		})
	}
}

// Fields named in Connection are hop-by-hop: a proxy between the tunnel
// client and the application removes them. A visitor must not be able to get
// the forwarding headers of the edge removed that way.
func TestConnectionHeaderCannotNameForwardingHeaders(t *testing.T) {
	for name, tc := range map[string]struct {
		lines string   // Connection header lines as sent
		want  []string // Connection header values as forwarded
	}{
		"among other tokens": {"Connection: keep-alive, X-Forwarded-For, x_real_ip, X-Forwarded-Proto\r\n", []string{"keep-alive"}},
		"alone":              {"Connection: X-Forwarded-For\r\n", nil},
		"with close":         {"Connection: X-Forwarded-Host, close, Forwarded\r\n", []string{"close"}},
		"on two lines":       {"Connection: keep-alive\r\nConnection: x-forwarded-for\r\n", []string{"keep-alive"}},
		"nothing to remove":  {"Connection: keep-alive,  X-Custom\r\n", []string{"keep-alive,  X-Custom"}},
	} {
		for _, position := range []string{"first request", "follow-up request"} {
			t.Run(name+", "+position, func(t *testing.T) {
				f := newFixture(t, Options{})
				sess := f.tunnel("abc")
				v := f.visit()

				var b *backend
				if position == "follow-up request" {
					v.send(get("/benign"))
					b = sess.accept(t)
					b.next()
					b.reply("ok")
					v.recvOK("ok")
				}
				v.send(get("/probe", tc.lines, "X-Custom: stays\r\n"))
				if b == nil {
					b = sess.accept(t)
				}
				req := b.next()
				require.Equal(t, tc.want, req.Header["Connection"])
				require.Equal(t, "stays", req.Header.Get("X-Custom"))
				requireEdgeForwarding(t, req.Request, "abc.localhost")
			})
		}
	}
}

// --- host of follow-up requests -----------------------------------------------------

func TestFollowUpRequestForAnotherHostEndsTheConnection(t *testing.T) {
	for name, second := range map[string]string{
		"another tunnel":        "GET /x HTTP/1.1\r\nHost: other.localhost\r\n\r\n",
		"the apex":              "GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n",
		"a foreign domain":      "GET /x HTTP/1.1\r\nHost: abc.localhost.evil.com\r\n\r\n",
		"an invalid host":       "GET /x HTTP/1.1\r\nHost: abc_.localhost\r\n\r\n",
		"no host":               "GET /x HTTP/1.0\r\n\r\n",
		"absolute request line": "GET http://other.localhost/x HTTP/1.1\r\nHost: abc.localhost\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Options{})
			sess := f.tunnel("abc")
			other := f.tunnel("other")
			v := f.visit()

			v.send(get("/first"))
			b := sess.accept(t)
			b.next()
			b.reply("ok")
			v.recvOK("ok")

			v.send(second)
			v.expectClosed(6*time.Second, "connection after a request for another host")
			b.expectEnd(6*time.Second, "stream after a request for another host")
			require.Zero(t, other.opens.Load(), "the other tunnel is not reached through this connection")
			require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
		})
	}
}

func TestFollowUpRequestWithEquivalentHostIsForwarded(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send(get("/first"))
	b := sess.accept(t)
	b.next()
	b.reply("1")
	v.recvOK("1")

	// X-Forwarded-Host carries the host in its normalised form, with the
	// port only when the Host header names one that is not the default.
	for i, tc := range []struct{ host, forwardedHost string }{
		{"ABC.LOCALHOST", "abc.localhost"},
		{"abc.localhost.", "abc.localhost"},
		{"abc.localhost:443", "abc.localhost"},
		{"abc.localhost:00443", "abc.localhost"},
		{"abc.localhost:", "abc.localhost"},
		{"Abc.Localhost.:8443", "abc.localhost:8443"},
		{"abc.localhost:08443", "abc.localhost:8443"},
		{"abc.localhost:80", "abc.localhost:80"}, // the default port of http, not of this connection
		{"abc.localhost:0", "abc.localhost:0"},
	} {
		v.send("GET /again HTTP/1.1\r\nHost: " + tc.host + "\r\n\r\n")
		req := b.next()
		require.Equal(t, tc.host, req.Host, "the Host header is passed on as sent")
		requireEdgeForwarding(t, req.Request, tc.forwardedHost)
		b.reply(strconv.Itoa(i))
		v.recvOK(strconv.Itoa(i))
	}
	// The absolute form names the same host.
	v.send("GET https://abc.localhost/abs?q=1 HTTP/1.1\r\nHost: ignored.example\r\n\r\n")
	req := b.next()
	require.Equal(t, "/abs?q=1", req.RequestURI)
	require.Equal(t, "abc.localhost", req.Host)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
}

// --- upgrade ----------------------------------------------------------------------------

func TestUpgradeRequestSwitchesToRawCopyInBothDirections(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send(get("/ws", forged, "Connection: keep-alive, Upgrade\r\n", "Upgrade: websocket\r\n", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"))
	b := sess.accept(t)
	req := b.next()
	require.Equal(t, "/ws", req.RequestURI)
	require.Equal(t, "websocket", req.Header.Get("Upgrade"))
	require.Equal(t, "keep-alive, Upgrade", req.Header.Get("Connection"))
	require.Equal(t, "dGhlIHNhbXBsZSBub25jZQ==", req.Header.Get("Sec-Websocket-Key"))
	requireEdgeForwarding(t, req.Request, "abc.localhost")

	b.write("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	res, _ := v.recv()
	require.Equal(t, 101, res.StatusCode)

	// From here on both directions carry bytes that are not HTTP.
	frame := "\x81\x05hello\x00\xff\r\n\r\nGET / HTTP/1.1\r\n"
	v.send(frame)
	require.Equal(t, frame, b.readExactly(len(frame)))
	back := "\x82\x03\x00\x01\x02 not a response \r\n\r\n"
	b.write(back)
	require.Equal(t, back, v.readExactly(len(back)))
}

func TestUpgradeHeaderWithoutConnectionTokenIsAnOrdinaryRequest(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	// No "upgrade" in Connection: a backend does not switch protocols for this.
	v.send(get("/not-ws", "Connection: keep-alive\r\n", "Upgrade: websocket\r\n"))
	b := sess.accept(t)
	b.next()
	b.reply("1")
	v.recvOK("1")

	v.send(get("/next", forged))
	req := b.next()
	require.Equal(t, "/next", req.RequestURI)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
}

func TestConnectRequestSwitchesToRawCopy(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send("CONNECT abc.localhost:443 HTTP/1.1\r\nHost: abc.localhost:443\r\n" + forged + "\r\n")
	b := sess.accept(t)
	req := b.next()
	require.Equal(t, "CONNECT", req.Method)
	require.Equal(t, "abc.localhost:443", req.RequestURI)
	requireEdgeForwarding(t, req.Request, "abc.localhost")

	established := "HTTP/1.1 200 Connection established\r\n\r\n"
	b.write(established)
	require.Equal(t, established, v.readExactly(len(established)))
	tunnelled := "\x16\x03\x01 raw tunnel bytes"
	v.send(tunnelled)
	require.Equal(t, tunnelled, b.readExactly(len(tunnelled)))
}

// --- request bodies -----------------------------------------------------------------------

func TestRequestBodiesAreForwardedByTheirFraming(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789abcdef"), 64*1024) // 1 MiB
	bigSum := sha256.Sum256(big)

	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	// First request: Content-Length body in the same write as the head.
	v.send("POST /cl HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\nhello world")
	b := sess.accept(t)
	req := b.next()
	require.Equal(t, "hello world", req.Body)
	require.EqualValues(t, 11, req.ContentLength)
	require.Equal(t, "text/plain", req.Header.Get("Content-Type"))
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	b.reply("1")
	v.recvOK("1")

	// Follow-up: the body arrives after a pause.
	v.send("PUT /late HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 6\r\n\r\n")
	time.Sleep(100 * time.Millisecond)
	v.send("late")
	time.Sleep(50 * time.Millisecond)
	v.send("r!")
	req = b.next()
	require.Equal(t, "PUT", req.Method)
	require.Equal(t, "later!", req.Body)
	b.reply("2")
	v.recvOK("2")

	// Chunked with a chunk extension and a trailer.
	v.send("POST /chunked HTTP/1.1\r\nHost: abc.localhost\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n" +
		"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Checksum: abc123\r\n\r\n")
	req = b.next()
	require.Equal(t, "hello world", req.Body)
	require.Equal(t, []string{"chunked"}, req.TransferEncoding)
	require.Equal(t, "abc123", req.Trailer.Get("X-Checksum"))
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	b.reply("3")
	v.recvOK("3")

	// The request after the chunked body starts at the right byte.
	v.send(get("/after-chunked", forged))
	req = b.next()
	require.Equal(t, "/after-chunked", req.RequestURI)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	b.reply("4")
	v.recvOK("4")

	// A large body.
	go func() {
		_, _ = v.c.Write([]byte("POST /big HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: " + strconv.Itoa(len(big)) + "\r\n\r\n"))
		_, _ = v.c.Write(big)
	}()
	req = b.next()
	require.Len(t, req.Body, len(big))
	require.Equal(t, bigSum, sha256.Sum256([]byte(req.Body)))
	b.reply("5")
	v.recvOK("5")

	// Methods and request targets that need care.
	v.send("HEAD /head HTTP/1.1\r\nHost: abc.localhost\r\n\r\n")
	req = b.next()
	require.Equal(t, "HEAD", req.Method)
	b.write("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
	_ = v.c.SetReadDeadline(time.Now().Add(8 * time.Second))
	res, err := http.ReadResponse(v.br, &http.Request{Method: "HEAD"})
	require.NoError(t, err)
	require.Equal(t, 200, res.StatusCode)

	v.send("OPTIONS * HTTP/1.1\r\nHost: abc.localhost\r\n\r\n")
	req = b.next()
	require.Equal(t, "OPTIONS", req.Method)
	require.Equal(t, "*", req.RequestURI)
	b.reply("7")
	v.recvOK("7")

	require.EqualValues(t, 1, sess.opens.Load())
}

func TestChunkedBodyOnTheFirstRequest(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send("POST /chunked HTTP/1.1\r\nHost: abc.localhost\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum, X-Other\r\n\r\n" +
		"3\r\nabc\r\n")
	time.Sleep(50 * time.Millisecond)
	v.send("4;x=y\r\ndefg\r\n0\r\nX-Checksum: sum\r\nX-Other: o\r\n\r\n" + get("/next", forged))

	b := sess.accept(t)
	req := b.next()
	require.Equal(t, "abcdefg", req.Body)
	require.Equal(t, "sum", req.Trailer.Get("X-Checksum"))
	require.Equal(t, "o", req.Trailer.Get("X-Other"))
	require.NotContains(t, req.Header, "Content-Length")
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	b.reply("1")

	req = b.next()
	require.Equal(t, "/next", req.RequestURI)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	b.reply("2")
	v.recvOK("1")
	v.recvOK("2")
}

func TestAbsoluteFormOnTheFirstRequest(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send("GET https://abc.localhost/abs?q=1 HTTP/1.1\r\nHost: ignored.example\r\n" + forged + "\r\n")
	b := sess.accept(t)
	req := b.next()
	require.Equal(t, "/abs?q=1", req.RequestURI)
	require.Equal(t, "abc.localhost", req.Host)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
}

func TestExpectContinueIsAnsweredByTheBackend(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send("POST /upload HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n")
	b := sess.accept(t)

	// The backend sees the head before any body byte exists.
	_ = b.c.SetReadDeadline(time.Now().Add(8 * time.Second))
	req, err := http.ReadRequest(b.br)
	require.NoError(t, err)
	require.Equal(t, "100-continue", req.Header.Get("Expect"))
	b.write("HTTP/1.1 100 Continue\r\n\r\n")

	res, _ := v.recv()
	require.Equal(t, 100, res.StatusCode)
	v.send("data")
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, "data", string(body))
	b.reply("stored")
	v.recvOK("stored")
}

// The response direction is not parsed: what the backend writes arrives byte
// for byte, however unusual.
func TestResponsesAreCopiedVerbatim(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send(get("/"))
	b := sess.accept(t)
	b.next()
	raw := "HTTP/1.1 200 OK\r\nx-WeIrD-cAsE:   spaced \r\nZ-Last: 1\r\nA-First: 2\r\nTransfer-Encoding: chunked\r\n\r\n2;ext\r\nok\r\n0\r\n\r\n"
	b.write(raw)
	require.Equal(t, raw, v.readExactly(len(raw)))
}

// --- the body is not read through r.Body after Hijack --------------------------------------

type spyBody struct {
	io.ReadCloser
	reads *int
}

func (s spyBody) Read(p []byte) (int, error) {
	*s.reads++
	return s.ReadCloser.Read(p)
}

func TestRequestBodyIsNotReadThroughTheServersBody(t *testing.T) {
	f := newFixture(t, Options{})
	reads := 0
	f.wrapHandler = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = spyBody{ReadCloser: r.Body, reads: &reads}
			next.ServeHTTP(w, r)
		})
	}
	sess := f.tunnel("abc")
	v := f.visit()

	v.send("POST /upload HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 10\r\n\r\n01234")
	time.Sleep(50 * time.Millisecond)
	v.send("56789" + get("/next"))

	b := sess.accept(t)
	req := b.next()
	require.Equal(t, "0123456789", req.Body, "the body reaches the backend complete")
	b.reply("1")
	req = b.next()
	require.Equal(t, "/next", req.RequestURI, "and the next request starts right after it")
	b.reply("2")
	v.recvOK("1")
	v.recvOK("2")
	require.Zero(t, reads, "r.Body was read after the connection was hijacked")
}

// --- malformed and hostile follow-up requests -------------------------------------------------

func TestMalformedFollowUpRequestEndsTheConnection(t *testing.T) {
	smuggled := "GET /smuggled HTTP/1.1\r\nHost: abc.localhost\r\nX-Forwarded-For: 6.6.6.6\r\n\r\n"
	for name, second := range map[string]string{
		"not http":                      "\x16\x03\x01\x02\x00 this is not a request\r\n\r\n" + smuggled,
		"negative content length":       "POST /a HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: -5\r\n\r\n" + smuggled,
		"content length not a number":   "POST /a HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 5x\r\n\r\nhello" + smuggled,
		"two different content lengths": "POST /a HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello" + smuggled,
		"content length list":           "POST /a HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 5, 6\r\n\r\nhello" + smuggled,
		"content length overflow":       "POST /a HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 99999999999999999999999\r\n\r\nhello" + smuggled,
		"unknown transfer encoding":     "POST /a HTTP/1.1\r\nHost: abc.localhost\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n" + smuggled,
		"two transfer encodings":        "POST /a HTTP/1.1\r\nHost: abc.localhost\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n" + smuggled,
		"space before the colon":        "GET /a HTTP/1.1\r\nHost: abc.localhost\r\nX-Forwarded-For : 6.6.6.6\r\n\r\n" + smuggled,
		"bad chunk size":                "POST /a HTTP/1.1\r\nHost: abc.localhost\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n" + smuggled,
		"chunk size overflow":           "POST /a HTTP/1.1\r\nHost: abc.localhost\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffff\r\nhello\r\n0\r\n\r\n" + smuggled,
		"bad http version":              "GET /a HTTP/9.9.9\r\nHost: abc.localhost\r\n\r\n" + smuggled,
		"invalid header name":           "GET /a HTTP/1.1\r\nHost: abc.localhost\r\nX-Bad(Name): 1\r\n\r\n" + smuggled,
		"control character in a value":  "GET /a HTTP/1.1\r\nHost: abc.localhost\r\nX-Value: a\x00b\r\n\r\n" + smuggled,
		"two host lines":                "GET /a HTTP/1.1\r\nHost: abc.localhost\r\nHost: other.localhost\r\n\r\n" + smuggled,
		"two host lines, other first":   "GET /a HTTP/1.1\r\nHost: other.localhost\r\nHost: abc.localhost\r\n\r\n" + smuggled,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Options{})
			sess := f.tunnel("abc")
			other := f.tunnel("other")
			v := f.visit()

			v.send(get("/first"))
			b := sess.accept(t)
			b.next()
			b.reply("ok")
			v.recvOK("ok")

			// The backend keeps reading: a request whose head is in order and
			// whose body is not is forwarded up to the fault.
			received := make(chan string, 1)
			go func() {
				_ = b.c.SetReadDeadline(time.Now().Add(8 * time.Second))
				rest, _ := io.ReadAll(b.br)
				received <- string(rest)
			}()

			v.send(second)
			v.expectClosed(6*time.Second, "connection after a malformed request")

			// Whatever part of the malformed request reached the backend before
			// the edge gave up: the request behind it never does.
			rest := <-received
			require.NotContains(t, rest, "smuggled")
			require.NotContains(t, rest, "6.6.6.6")
			require.NotContains(t, rest, "other.localhost")
			require.Zero(t, other.opens.Load())
			require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
		})
	}
}

// Content-Length together with Transfer-Encoding is the classic smuggling
// vector: two parsers that disagree about where the request ends.
func TestContentLengthWithTransferEncodingCannotSmuggle(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send(get("/first"))
	b := sess.accept(t)
	b.next()
	b.reply("ok")
	v.recvOK("ok")

	v.send("POST /a HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"0\r\n\r\n" +
		"GET /second HTTP/1.1\r\nHost: abc.localhost\r\nX-Forwarded-For: 6.6.6.6\r\n\r\n")

	// The edge either refuses the ambiguous request or forwards it with a
	// single framing. Everything the backend receives then reads the same
	// for every parser and carries the forwarding headers of the edge.
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = v.c.Close() // lets the stream end if the edge kept the connection
	}()
	_ = b.c.SetReadDeadline(time.Now().Add(8 * time.Second))
	raw, _ := io.ReadAll(b.br)
	require.NotContains(t, string(raw), "Content-Length: 4", "both framings reached the backend")
	require.NotContains(t, string(raw), "6.6.6.6", "a forged forwarding header reached the backend")
	rest := bufio.NewReader(bytes.NewReader(raw))
	for {
		req, err := http.ReadRequest(rest)
		if err != nil {
			break
		}
		_, err = io.ReadAll(req.Body)
		require.NoError(t, err)
		requireEdgeForwarding(t, req, "abc.localhost")
	}
}

func TestVisitorDisconnectsInTheMiddleOfARequest(t *testing.T) {
	for name, partial := range map[string]string{
		"in the head": "POST /cut HTTP/1.1\r\nHost: abc.localhost\r\nContent-Le",
		"in the body": "POST /cut HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 100\r\n\r\nonly ten b",
		"in a chunk":  "POST /cut HTTP/1.1\r\nHost: abc.localhost\r\nTransfer-Encoding: chunked\r\n\r\n64\r\nonly ten b",
	} {
		for _, position := range []string{"first request", "follow-up request"} {
			t.Run(name+", "+position, func(t *testing.T) {
				f := newFixture(t, Options{})
				sess := f.tunnel("abc")
				v := f.visit()

				var b *backend
				if position == "follow-up request" {
					v.send(get("/first"))
					b = sess.accept(t)
					b.next()
					b.reply("ok")
					v.recvOK("ok")
				}
				v.send(partial)
				time.Sleep(50 * time.Millisecond)
				require.NoError(t, v.c.Close())

				var stream net.Conn
				if b != nil {
					stream = b.c
				} else {
					select {
					case st := <-sess.streams:
						stream = st.(net.Conn)
					case <-time.After(300 * time.Millisecond):
						// A first request cut short in its head never reaches the edge.
					}
				}
				if stream != nil {
					_ = stream.SetReadDeadline(time.Now().Add(8 * time.Second))
					_, err := io.Copy(io.Discard, stream)
					var ne net.Error
					require.False(t, errors.As(err, &ne) && ne.Timeout(), "the stream of the dropped connection was left open")
				}
				require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond,
					"the slot of the dropped connection was not released")
			})
		}
	}
}

func TestBackendEndsTheStream(t *testing.T) {
	t.Run("in the middle of a request body", func(t *testing.T) {
		f := newFixture(t, Options{})
		sess := f.tunnel("abc")
		v := f.visit()

		v.send("POST /upload HTTP/1.1\r\nHost: abc.localhost\r\nContent-Length: 1000000\r\n\r\npart")
		b := sess.accept(t)
		require.NoError(t, b.c.Close())
		v.expectClosed(6*time.Second, "connection whose backend went away")
		require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
	})

	t.Run("after a response", func(t *testing.T) {
		f := newFixture(t, Options{})
		sess := f.tunnel("abc")
		v := f.visit()

		v.send(get("/"))
		b := sess.accept(t)
		b.next()
		b.write("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
		require.NoError(t, b.c.Close())
		v.recvOK("ok")
		v.expectClosed(6*time.Second, "connection after the backend closed")
	})
}

// --- header size of follow-up requests ------------------------------------------------------------

// paddedRequest builds a GET request whose head is exactly size bytes long.
func paddedRequest(t *testing.T, path string, size int) string {
	t.Helper()
	const frame = "GET %s HTTP/1.1\r\nHost: abc.localhost\r\nX-Pad: %s\r\n\r\n"
	empty := strings.Replace(strings.Replace(frame, "%s", path, 1), "%s", "", 1)
	pad := size - len(empty)
	require.Positive(t, pad)
	req := strings.Replace(strings.Replace(frame, "%s", path, 1), "%s", strings.Repeat("p", pad), 1)
	require.Len(t, req, size)
	return req
}

func TestFollowUpRequestHeadIsLimited(t *testing.T) {
	for _, tc := range []struct {
		name     string
		limit    int // Options.MaxHeaderBytes
		headSize int
		accepted bool
	}{
		{"default, exactly 64 KiB", 0, 65536, true},
		{"default, one byte more", 0, 65537, false},
		{"default, far more", 0, 300000, false},
		{"8 KiB, exactly", 8192, 8192, true},
		{"8 KiB, one byte more", 8192, 8193, false},
		// The limit cannot be disabled: a negative value selects the default.
		{"negative, exactly 64 KiB", -1, 65536, true},
		{"negative, one byte more", -1, 65537, false},
		{"negative, far more", -1, 300000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, Options{MaxHeaderBytes: tc.limit})
			sess := f.tunnel("abc")
			v := f.visit()

			v.send(get("/first"))
			b := sess.accept(t)
			b.next()
			b.reply("ok")
			v.recvOK("ok")

			big := paddedRequest(t, "/big", tc.headSize)
			go func() { _, _ = v.c.Write([]byte(big + get("/after"))) }()

			if tc.accepted {
				req := b.next()
				require.Equal(t, "/big", req.RequestURI)
				wantPad := tc.headSize - len("GET /big HTTP/1.1\r\nHost: abc.localhost\r\nX-Pad: \r\n\r\n")
				require.Len(t, req.Header.Get("X-Pad"), wantPad)
				b.reply("big")
				req = b.next()
				require.Equal(t, "/after", req.RequestURI)
				b.reply("after")
				v.recvOK("big")
				v.recvOK("after")
				return
			}
			v.expectClosed(6*time.Second, "connection after an oversized request head")
			_ = b.c.SetReadDeadline(time.Now().Add(8 * time.Second))
			rest, _ := io.ReadAll(b.br)
			require.Empty(t, rest, "no part of the oversized request is forwarded")
		})
	}
}
