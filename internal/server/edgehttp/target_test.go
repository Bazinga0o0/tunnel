package edgehttp

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// rawHead reads the head of one request as raw lines and returns the request
// line without its line end.
func (b *backend) rawHead() string {
	b.t.Helper()
	requestLine := ""
	for i := 0; ; i++ {
		line, err := b.br.ReadString('\n')
		require.NoError(b.t, err)
		if i == 0 {
			requestLine = strings.TrimSuffix(line, "\r\n")
		}
		if line == "\r\n" {
			return requestLine
		}
	}
}

// An origin-form request target reaches the backend byte for byte as the
// visitor sent it, on the first request and on those that follow.
func TestRequestTargetIsForwardedByteForByte(t *testing.T) {
	for _, target := range []string{
		"/plain",
		"/",
		"/?",
		"/a?",
		`/a"b`,
		"/a%22b",
		"/a%2Fb/../c/./d",
		"/a//b",
		`/a\b`,
		"/a|b^c`d{e}",
		"/<script>",
		"/a#fragment",
		"/caf\xc3\xa9",
		"/\xff\xfe",
		`/p?q="x"&y=%2F&z=<>`,
		"/a;param=1?x=1;y=2",
		"/a?b?c#d",
		"/%41", // an escape that the edge must not decode
	} {
		t.Run(target, func(t *testing.T) {
			f := newFixture(t, Options{})
			sess := f.tunnel("abc")
			v := f.visit()

			v.send("GET " + target + " HTTP/1.1\r\nHost: abc.localhost\r\n\r\n")
			b := sess.accept(t)
			require.Equal(t, "GET "+target+" HTTP/1.1", b.rawHead(), "first request")
			b.reply("1")
			v.recvOK("1")

			v.send("GET " + target + " HTTP/1.1\r\nHost: abc.localhost\r\n\r\n")
			require.Equal(t, "GET "+target+" HTTP/1.1", b.rawHead(), "follow-up request")
			b.reply("2")
			v.recvOK("2")
		})
	}
}

// Targets that are not carried byte for byte: a path that starts with two
// slashes, the absolute form and "*". They are written from the parsed URL.
func TestRequestTargetsWrittenFromTheParsedURL(t *testing.T) {
	for _, tc := range []struct{ method, target, want string }{
		{"GET", "//double/slash?q=1", "//double/slash?q=1"},
		{"GET", `//a"b`, "//a%22b"},
		{"GET", "https://abc.localhost/abs?q=1", "/abs?q=1"},
		{"GET", "https://abc.localhost", "/"},
		{"OPTIONS", "*", "*"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			f := newFixture(t, Options{})
			sess := f.tunnel("abc")
			v := f.visit()

			v.send(get("/first"))
			b := sess.accept(t)
			b.next()
			b.reply("1")
			v.recvOK("1")

			v.send(tc.method + " " + tc.target + " HTTP/1.1\r\nHost: abc.localhost\r\n\r\n")
			require.Equal(t, tc.method+" "+tc.want+" HTTP/1.1", b.rawHead())
		})
	}
}

// A target that http.ReadRequest refuses is still refused.
func TestInvalidRequestTargetIsNotForwarded(t *testing.T) {
	for _, target := range []string{"/a%zzb", "/a\x7fb", "/a\x01b", "no-slash", "/a b"} {
		t.Run(target, func(t *testing.T) {
			f := newFixture(t, Options{})
			sess := f.tunnel("abc")
			v := f.visit()

			v.send(get("/first"))
			b := sess.accept(t)
			b.next()
			b.reply("1")
			v.recvOK("1")

			v.send("GET " + target + " HTTP/1.1\r\nHost: abc.localhost\r\n\r\n")
			b.expectEnd(6*time.Second, "stream after a request with an invalid target")
		})
	}
}
