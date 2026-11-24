package edgehttp

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// headerTimeout is the server's ReadHeaderTimeout in the tests below. A
// connection the edge has answered without hijacking it must be closed
// before it runs out: after the head nothing else bounds the connection.
const headerTimeout = 2 * time.Second

// noStreams is a registered session that is not a TunnelOpener.
type noStreams struct{ id string }

func (n noStreams) ID() string { return n.id }

// Every answer that the edge writes itself, without hijacking, closes the
// connection, also when the request announced a body that never arrives.
// Otherwise net/http waits for that body (up to 256 KiB) with no deadline at
// all: the header timeout is over, the idle timeout applies only between
// requests and the public server has no read or write timeout.
func TestAnswersWithoutHijackCloseTheConnection(t *testing.T) {
	bodies := map[string]string{
		"content-length": "Content-Length: 100\r\n",
		"chunked":        "Transfer-Encoding: chunked\r\n",
		"no body":        "",
	}
	cases := []struct {
		name   string
		host   string
		status int
	}{
		{"unknown tunnel", "nosuch.localhost", http.StatusNotFound},
		{"the domain itself", "localhost", http.StatusNotFound},
		{"two labels", "a.b.localhost", http.StatusNotFound},
		{"invalid host", "bad_host.localhost", http.StatusBadRequest},
		{"stream refused", "refuses.localhost", http.StatusBadGateway},
		{"session without streams", "nostreams.localhost", http.StatusInternalServerError},
	}
	f := newFixtureWith(t, Options{}, func(s *http.Server) { s.ReadHeaderTimeout = headerTimeout })
	refuses := f.tunnel("refuses")
	refuses.openHook = func(int32) error { return errors.New("session shutdown") }
	require.NoError(t, f.reg.RegisterHTTP("nostreams", noStreams{id: "no-streams"}))

	for _, c := range cases {
		for bodyName, framing := range bodies {
			t.Run(c.name+"/"+bodyName, func(t *testing.T) {
				v := f.visit()
				v.t = t
				v.send("POST /upload HTTP/1.1\r\nHost: " + c.host + "\r\n" + framing + "\r\n")
				start := time.Now()
				res, _ := v.recv()
				require.Equal(t, c.status, res.StatusCode)
				require.True(t, res.Close, "the answer must say Connection: close")
				v.expectClosed(headerTimeout-time.Since(start), "after the answer")
			})
		}
	}
}

// The 503 of a connection limit is an answer without hijack as well.
func TestLimitAnswerClosesTheConnectionWithAnUnsentBody(t *testing.T) {
	f := newFixtureWith(t, Options{MaxConnsPerTunnel: 1}, func(s *http.Server) { s.ReadHeaderTimeout = headerTimeout })
	sess := f.tunnel("myapp")
	hold(t, f, sess, "myapp.localhost", 1)

	for _, framing := range []string{"Content-Length: 100\r\n", "Transfer-Encoding: chunked\r\n"} {
		v := f.visit()
		v.send("POST /over HTTP/1.1\r\nHost: myapp.localhost\r\n" + framing + "\r\n")
		start := time.Now()
		res, _ := v.recv()
		require.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
		require.True(t, res.Close)
		v.expectClosed(headerTimeout-time.Since(start), framing)
	}
}
