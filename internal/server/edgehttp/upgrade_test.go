package edgehttp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// The visitor-to-backend direction becomes a raw copy only after the backend
// has agreed: 101 to an Upgrade request, 2xx to CONNECT, and only for the
// first request of a connection. Until then, and in every other case, the
// visitor's bytes are parsed and forwarded request by request.

const (
	upgradeHeaders = "Connection: Upgrade\r\nUpgrade: websocket\r\n"
	switching      = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
)

// expectSilent asserts that nothing arrives at the backend for d.
func (b *backend) expectSilent(d time.Duration, what string) {
	b.t.Helper()
	_ = b.c.SetReadDeadline(time.Now().Add(d))
	p, err := b.br.Peek(1)
	var ne net.Error
	require.True(b.t, errors.As(err, &ne) && ne.Timeout(), "%s: the backend received %q (err %v)", what, p, err)
	_ = b.c.SetReadDeadline(time.Now().Add(8 * time.Second))
}

// head reads the head of one request and leaves its body unread.
func (b *backend) head() *http.Request {
	b.t.Helper()
	req, err := http.ReadRequest(b.br)
	require.NoError(b.t, err)
	return req
}

// An upgrade that the backend does not perform must not open a way around
// the forwarding headers: the request behind it is rewritten like any other.
func TestUpgradeAnswered200KeepsRewritingRequests(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send(get("/not-ws", upgradeHeaders) + get("/smuggled", forged))
	b := sess.accept(t)
	req := b.next()
	require.Equal(t, "/not-ws", req.RequestURI)
	require.Equal(t, "websocket", req.Header.Get("Upgrade"), "the first request carries its upgrade to the backend")
	require.Equal(t, "Upgrade", req.Header.Get("Connection"))
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	b.expectSilent(200*time.Millisecond, "before the backend answered the upgrade request")

	b.reply("no upgrade here")
	v.recvOK("no upgrade here")
	req = b.next()
	require.Equal(t, "/smuggled", req.RequestURI)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	b.reply("2")
	v.recvOK("2")

	// The connection goes on as a keep-alive connection.
	v.send(get("/third", forged))
	req = b.next()
	require.Equal(t, "/third", req.RequestURI)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	b.reply("3")
	v.recvOK("3")
	require.EqualValues(t, 1, sess.opens.Load())
}

func TestUpgradeAnswered200AgainstRealBackend(t *testing.T) {
	f := newFixture(t, Options{})
	rec := &record{}
	realTunnel(t, f, "abc", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r, "")
		fmt.Fprint(w, "plain ", r.URL.Path) // the backend knows no upgrade
	}))

	v := f.visit()
	v.send(get("/not-ws", upgradeHeaders) + get("/smuggled", forged))
	v.recvOK("plain /not-ws")
	v.recvOK("plain /smuggled")
	v.send(get("/third", forged))
	v.recvOK("plain /third")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Len(t, rec.reqs, 3)
	for i, req := range rec.reqs {
		requireEdgeForwarding(t, req, "abc.localhost")
		require.Equal(t, "", req.Header.Get("X-Real-Ip"), "request %d", i)
	}
}

// Bytes that the visitor sends right behind its upgrade request wait for the
// backend's answer. They are not forwarded before it and not lost after it.
func TestBytesBehindTheUpgradeRequestWaitForTheDecision(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	frame := "\x81\x05hello not http\r\n\r\nGET /x HTTP/1.1\r\n"
	v.send(get("/ws", forged, upgradeHeaders) + frame)
	b := sess.accept(t)
	req := b.next()
	require.Equal(t, "/ws", req.RequestURI)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
	b.expectSilent(200*time.Millisecond, "before the backend answered the upgrade request")

	b.write(switching)
	require.Equal(t, switching, v.readExactly(len(switching)), "the answer reaches the visitor byte for byte")
	require.Equal(t, frame, b.readExactly(len(frame)), "the bytes sent ahead arrive, unchanged, after the switch")

	back := "\x82\x03\x00\x01\x02 not a response \r\n\r\n"
	b.write(back)
	require.Equal(t, back, v.readExactly(len(back)))
	more := "\x81\x03abc"
	v.send(more)
	require.Equal(t, more, b.readExactly(len(more)))
}

// Interim responses are passed on and do not decide anything: the edge waits
// for 101 or for the final status.
func TestUpgradeWithExpectContinueAndBody(t *testing.T) {
	// A header line longer than the buffer the answer is read through.
	longHint := "HTTP/1.1 103 Early Hints\r\nLink: <" + strings.Repeat("x", 2*answerBufferSize) + ">\r\n\r\n"
	for _, tc := range []struct {
		name     string
		interims []string // sent after the body arrived, before the final answer
		final    string
		raw      bool
	}{
		{"switches", []string{"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"}, switching, true},
		{"switches after odd interim responses", []string{"HTTP/1.0 100 Continue\n\n", longHint, "HTTP/1.1 102 Processing\r\n\r\n"}, switching, true},
		{"stays http", []string{"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"},
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, Options{})
			sess := f.tunnel("abc")
			v := f.visit()

			v.send("POST /ws HTTP/1.1\r\nHost: abc.localhost\r\n" + forged + upgradeHeaders + "Expect: 100-continue\r\nContent-Length: 5\r\n\r\n")
			b := sess.accept(t)
			req := b.head()
			require.Equal(t, "100-continue", req.Header.Get("Expect"))
			requireEdgeForwarding(t, req, "abc.localhost")

			// The visitor sends its body only after the backend's go-ahead,
			// and more right behind it in the same write: the edge reads
			// both at once and has to keep what follows the body.
			cont := "HTTP/1.1 100 Continue\r\n\r\n"
			b.write(cont)
			require.Equal(t, cont, v.readExactly(len(cont)))
			behind := get("/behind", forged)
			v.send("hello" + behind)
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			require.Equal(t, "hello", string(body))

			for _, interim := range tc.interims {
				go func() { _, _ = b.c.Write([]byte(interim)) }() // may be larger than the buffers on the way
				require.Equal(t, interim, v.readExactly(len(interim)))
			}
			b.expectSilent(200*time.Millisecond, "before the backend's final answer to the upgrade request")

			b.write(tc.final)
			require.Equal(t, tc.final, v.readExactly(len(tc.final)))
			if tc.raw {
				require.Equal(t, behind, b.readExactly(len(behind)), "after the switch the visitor's bytes pass unchanged")
				return
			}
			next := b.next()
			require.Equal(t, "/behind", next.RequestURI)
			requireEdgeForwarding(t, next.Request, "abc.localhost")
		})
	}
}

// A backend that never answers the upgrade request holds the connection only
// until the idle timeout; nothing behind the request is forwarded meanwhile.
func TestBackendNeverAnswersTheUpgrade(t *testing.T) {
	f := newFixture(t, Options{IdleTimeout: 400 * time.Millisecond})
	sess := f.tunnel("abc")
	v := f.visit()

	start := time.Now() // before the last byte moves
	v.send(get("/ws", upgradeHeaders) + get("/smuggled", forged))
	b := sess.accept(t)
	require.Equal(t, "/ws", b.next().RequestURI)

	b.expectEnd(6*time.Second, "stream of an upgrade request that is never answered")
	v.expectClosed(6*time.Second, "connection of an upgrade request that is never answered")
	require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond,
		"the handler is still waiting for the backend's answer")
}

// The backend goes away without an answer: the waiting request side is
// released at once, not by the idle timeout.
func TestBackendEndsTheStreamInsteadOfAnsweringTheUpgrade(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send(get("/ws", upgradeHeaders) + get("/smuggled", forged))
	b := sess.accept(t)
	b.next()
	require.NoError(t, b.c.Close())

	v.expectClosed(6*time.Second, "connection whose backend left during the upgrade")
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond,
		"the handler is still waiting for the backend's answer")
}

// A panic while the answer is awaited releases the request side as well.
func TestPanicWhileTheUpgradeAnswerIsAwaited(t *testing.T) {
	f := newFixture(t, Options{})
	abc := f.tunnel("abc")
	abc.wrap = func(s protocol.Stream) protocol.Stream {
		if abc.opens.Load() == 1 {
			return &panicStream{Conn: s.(net.Conn), onRead: true}
		}
		return s
	}

	v := f.visit()
	v.send(get("/ws", upgradeHeaders) + get("/smuggled", forged))
	b := abc.accept(t)
	go func() { _, _ = io.Copy(io.Discard, b.c) }()
	v.expectClosed(6*time.Second, "connection whose response side panicked")
	// Twice: the drain of the retired stream reads it too, and its panic is
	// recovered and logged as well.
	require.Eventually(t, func() bool { return f.logs.count(slog.LevelError, "panic recovered") == 2 },
		6*time.Second, 5*time.Millisecond, "the panic is logged")
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond,
		"the handler is still waiting for the backend's answer")

	// The edge keeps serving.
	hold(t, f, abc, "abc.localhost", 1)
}

// An upgrade request that is not the first of its connection is forwarded as
// an ordinary request: without the Upgrade header and without the token that
// announces it.
func TestUpgradeAsSecondRequestIsForwardedWithoutUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name           string
		connection     string
		wantConnection []string
	}{
		{"upgrade only", "Connection: Upgrade\r\n", nil},
		{"with other tokens", "Connection: keep-alive, UPGRADE, X-Hop\r\n", []string{"keep-alive, X-Hop"}},
		{"in a second line", "Connection: keep-alive\r\nConnection: upgrade\r\n", []string{"keep-alive"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, Options{})
			sess := f.tunnel("abc")
			v := f.visit()

			v.send(get("/first"))
			b := sess.accept(t)
			b.next()
			b.reply("1")
			v.recvOK("1")

			v.send(get("/ws", forged, tc.connection, "Upgrade: websocket\r\n", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") +
				get("/after", forged))
			req := b.next()
			require.Equal(t, "/ws", req.RequestURI)
			require.Empty(t, req.Header["Upgrade"], "the Upgrade header of a later request is not forwarded")
			require.Equal(t, tc.wantConnection, req.Header["Connection"])
			require.Equal(t, "dGhlIHNhbXBsZSBub25jZQ==", req.Header.Get("Sec-Websocket-Key"))
			requireEdgeForwarding(t, req.Request, "abc.localhost")

			// No switch and no wait: the request behind it is parsed and
			// rewritten before the backend has answered.
			req = b.next()
			require.Equal(t, "/after", req.RequestURI)
			requireEdgeForwarding(t, req.Request, "abc.localhost")
			b.reply("2")
			b.reply("3")
			v.recvOK("2")
			v.recvOK("3")
		})
	}
}

func TestConnectAsSecondRequestEndsTheConnection(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send(get("/first"))
	b := sess.accept(t)
	b.next()
	b.reply("1")
	v.recvOK("1")

	v.send("CONNECT abc.localhost:443 HTTP/1.1\r\nHost: abc.localhost:443\r\n\r\n" + get("/smuggled", forged))
	b.expectEnd(6*time.Second, "stream after a CONNECT that is not the first request")
	v.expectClosed(6*time.Second, "connection after a CONNECT that is not the first request")
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// CONNECT switches on a 2xx answer only.
func TestConnectAnsweredWithARefusalKeepsRewritingRequests(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")
	v := f.visit()

	v.send("CONNECT abc.localhost:443 HTTP/1.1\r\nHost: abc.localhost:443\r\n\r\n" + get("/smuggled", forged))
	b := sess.accept(t)
	require.Equal(t, "CONNECT", b.next().Method)
	b.expectSilent(200*time.Millisecond, "before the backend answered the CONNECT request")

	refusal := "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
	b.write(refusal)
	require.Equal(t, refusal, v.readExactly(len(refusal)))
	req := b.next()
	require.Equal(t, "/smuggled", req.RequestURI)
	requireEdgeForwarding(t, req.Request, "abc.localhost")
}

// Answers that agree to nothing the request asked for never switch.
func TestAnswersThatDoNotAgreeToTheSwitch(t *testing.T) {
	connectRequest := "CONNECT abc.localhost:443 HTTP/1.1\r\nHost: abc.localhost:443\r\n\r\n"
	for _, tc := range []struct {
		name    string
		request string
		answer  string
	}{
		{"upgrade answered 2xx", get("/ws", upgradeHeaders), "HTTP/1.1 204 No Content\r\n\r\n"},
		{"upgrade answered with something that is not http", get("/ws", upgradeHeaders), "SSH-2.0-OpenSSH_9.6\r\n"},
		{"upgrade answered with a status that is not a number", get("/ws", upgradeHeaders), "HTTP/1.1 1O1 Switching Protocols\r\n\r\n"},
		{"upgrade answered with a four-digit status", get("/ws", upgradeHeaders), "HTTP/1.1 1010 Switching Protocols\r\n\r\n"},
		{"upgrade answered by another protocol version", get("/ws", upgradeHeaders), "HTTP/2.0 101 Switching Protocols\r\n\r\n"},
		{"upgrade answered in lower case", get("/ws", upgradeHeaders), "http/1.1 101 Switching Protocols\r\n\r\n"},
		{"upgrade answered with a space too many", get("/ws", upgradeHeaders), "HTTP/1.1  101 Switching Protocols\r\n\r\n"},
		{"upgrade answered with 101 in the second line", get("/ws", upgradeHeaders), "HTTP/1.1 200 OK\r\nX: HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n"},
		{"connect answered 101", connectRequest, switching},
		{"connect answered 3xx", connectRequest, "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\n\r\n"},
		{"connect answered 199", connectRequest, "HTTP/1.1 199 Odd\r\n\r\nHTTP/1.1 300 Multiple Choices\r\nContent-Length: 0\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, Options{})
			sess := f.tunnel("abc")
			v := f.visit()

			v.send(tc.request + get("/smuggled", forged))
			b := sess.accept(t)
			b.next()
			b.write(tc.answer)
			require.Equal(t, tc.answer, v.readExactly(len(tc.answer)))
			req := b.next()
			require.Equal(t, "/smuggled", req.RequestURI)
			requireEdgeForwarding(t, req.Request, "abc.localhost")
		})
	}
}

// --- a refused follow-up request and the answers still owed ------------------------

// yamuxClient registers a tunnel for abc on a real yamux session and returns
// the tunnel client's side of it. A yamux stream can be half-closed, which a
// pipe cannot.
func yamuxClient(t *testing.T, f *fixture) protocol.Session {
	t.Helper()
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
	return client
}

// A follow-up request that the edge refuses ends the visitor's side of the
// connection. The answer that the backend still owes to the request before
// it is delivered.
func TestRefusedFollowUpRequestDoesNotCutThePendingResponse(t *testing.T) {
	for name, second := range map[string]string{
		"another host":     "GET /x HTTP/1.1\r\nHost: other.localhost\r\n\r\n",
		"malformed":        "\x16\x03\x01 this is not a request\r\n\r\n",
		"bad header name":  "GET /x HTTP/1.1\r\nHost: abc.localhost\r\nX-Bad(Name): 1\r\n\r\n",
		"late connect":     "CONNECT abc.localhost:443 HTTP/1.1\r\nHost: abc.localhost:443\r\n\r\n",
		"malformed body":   "POST /x HTTP/1.1\r\nHost: abc.localhost\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
		"oversized header": "GET /x HTTP/1.1\r\nHost: abc.localhost\r\nX-Pad: " + strings.Repeat("p", 70000) + "\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Options{})
			client := yamuxClient(t, f)

			// The tunnel client answers the first request only after the edge
			// has ended its side of the stream.
			clientErr := make(chan error, 1)
			go func() {
				st, err := client.AcceptStream()
				if err != nil {
					clientErr <- err
					return
				}
				defer st.Close()
				if _, err := protocol.ReadStreamHeader(st); err != nil {
					clientErr <- err
					return
				}
				br := bufio.NewReader(st)
				if _, err := http.ReadRequest(br); err != nil {
					clientErr <- err
					return
				}
				if _, err := io.Copy(io.Discard, br); err != nil { // returns at the end of the edge's side
					clientErr <- err
					return
				}
				_, err = st.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nlate"))
				clientErr <- err
			}()

			v := f.visit()
			go func() { _, _ = v.c.Write([]byte(get("/slow") + second)) }()
			v.recvOK("late")
			require.NoError(t, <-clientErr)
			v.expectClosed(6*time.Second, "connection after the pending response was delivered")
			require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
		})
	}
}

// lateAnswer plays the tunnel client: it takes one stream, reads the first
// request, waits until the edge has ended its side of the stream and only
// then answers "late". The channel reports how that went.
func lateAnswer(client protocol.Session) <-chan error {
	result := make(chan error, 1)
	go func() {
		st, err := client.AcceptStream()
		if err != nil {
			result <- err
			return
		}
		defer st.Close()
		if _, err := protocol.ReadStreamHeader(st); err != nil {
			result <- err
			return
		}
		br := bufio.NewReader(st)
		if _, err := http.ReadRequest(br); err != nil {
			result <- err
			return
		}
		if _, err := io.Copy(io.Discard, br); err != nil { // returns at the end of the edge's side
			result <- err
			return
		}
		_, err = st.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nlate"))
		result <- err
	}()
	return result
}

// When the edge refuses a request it stops reading, and part of what the
// visitor sent may be left unread. Closing the connection in that state makes
// the system send a reset, and a reset can destroy the answer that is still
// on its way to the visitor. The visitor here reads nothing until the edge
// has closed the connection, and must still find the answer.
func TestRefusedRequestWithUnreadBytesKeepsThePendingResponse(t *testing.T) {
	for name, second := range map[string]string{
		// The edge gives up after 64 KiB of the head.
		"oversized header": "GET /x HTTP/1.1\r\nHost: abc.localhost\r\nX-Pad: " + strings.Repeat("p", 200000) + "\r\n\r\n",
		// The edge gives up at the chunk size.
		"malformed body": "POST /x HTTP/1.1\r\nHost: abc.localhost\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n" + strings.Repeat("b", 200000),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Options{})
			answered := lateAnswer(yamuxClient(t, f))

			v := f.visit()
			go func() { _, _ = v.c.Write([]byte(get("/slow") + second)) }()
			select {
			case err := <-answered:
				require.NoError(t, err)
			case <-time.After(15 * time.Second):
				t.Fatal("the backend never saw the end of the edge's side of the stream")
			}
			require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond,
				"the edge did not close the connection")
			time.Sleep(200 * time.Millisecond) // a reset, if there is one, has arrived by now

			v.recvOK("late")
			v.expectClosed(6*time.Second, "connection after the pending response was delivered")
		})
	}
}
