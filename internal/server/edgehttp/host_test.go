package edgehttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// A name of four labels and exactly 253 characters.
var host253 = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)

func TestNormalizeHostAccepts(t *testing.T) {
	require.Len(t, host253, 253)
	for _, tc := range []struct{ in, want string }{
		// Hosts as real clients send them.
		{"example.com", "example.com"},
		{"sub.example.com", "sub.example.com"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"a-b.example.com", "a-b.example.com"},
		{"123.example.com", "123.example.com"},
		{"localhost", "localhost"},
		{"a.b", "a.b"},
		// Labels that only look like numbers: hexadecimal in another place
		// than the last, or not hexadecimal after all.
		{"0x7f.example.com", "0x7f.example.com"},
		{"abc.0xg", "abc.0xg"},
		{"abc.x0", "abc.x0"},
		{"abc.00x1", "abc.00x1"},
		{"0xyz", "0xyz"},
		// One port is stripped.
		{"example.com:8443", "example.com"},
		{"abc.localhost:8443", "abc.localhost"},
		{"example.com:0", "example.com"},
		{"example.com:65535", "example.com"},
		{"example.com:00080", "example.com"},
		{"example.com:", "example.com"},
		// One trailing dot is stripped, also in front of a port.
		{"example.com.", "example.com"},
		{"example.com.:443", "example.com"},
		// Lower-casing.
		{"EXAMPLE.com", "example.com"},
		{"ABC.Example.COM.:443", "abc.example.com"},
		// Length limits: 63 per label, 253 in total.
		{strings.Repeat("a", 63) + ".example.com", strings.Repeat("a", 63) + ".example.com"},
		{host253, host253},
		{host253 + ".", host253},
		{strings.ToUpper(host253) + ".:443", host253},
	} {
		got, ok := NormalizeHost(tc.in)
		require.True(t, ok, "%q must be accepted", tc.in)
		require.Equal(t, tc.want, got, "input %q", tc.in)
	}
}

func TestNormalizeHostRejects(t *testing.T) {
	for _, in := range []string{
		// Nothing there.
		"", ".", ":", ":80", "..",
		// Ports.
		"example.com:80:90", "example.com:http", "example.com:65536", "example.com:123456", "example.com:000080",
		"example.com:-1", "example.com: 80", "example.com:80 ", "example.com:\uff18\uff10", "example.com:+80",
		// Empty labels.
		"example.com..", ".example.com", "a..b", "example.com.:443.",
		// Characters outside letters, digits and hyphen.
		"a_b.example.com", "abc%2eexample.com", "user@example.com", "example.com/path", "example.com?x",
		"example.com#f", "*.example.com", "exam*ple.com", "exa mple.com",
		// Hyphen at the edge of a label.
		"-a.example.com", "a-.example.com", "example.-com", "example.com-",
		// Non-ASCII, including characters that fold to ASCII letters.
		"exämple.com", "abc.\u212aelvin.example", "abc.\u0130stanbul.example", "ex\uff41mple.com", "\u0435\u0445ample.com",
		// White space and control characters.
		" example.com", "example.com ", "example.com\t", "example.com\u00a0", "exa\u200bmple.com",
		"example.com\x00", "example.com\n", "example.com\r\nX-Evil: 1", "\ufeffexample.com",
		// IP literals are addresses, not host names.
		"[::1]", "[::1]:443", "::1", "[2001:db8::1]:443", "127.0.0.1", "127.0.0.1:8443", "1.2.3.4.",
		"2130706433", "example.123",
		// ... and so is a last label in hexadecimal: 0x or 0X, followed by hex
		// digits or by nothing.
		"0x7f000001", "0X7F000001", "1.0x7f", "127.0.0.0x1", "example.0x1F", "abc.0x", "abc.0X",
		"0x7f000001:8443", "0x7f000001.", "abc.localhost.0xA:443",
		// Too long.
		strings.Repeat("a", 64) + ".example.com",
		host253 + "d",
		host253 + "d.",
	} {
		got, ok := NormalizeHost(in)
		require.False(t, ok, "%q must be rejected, got %q", in, got)
		require.Empty(t, got, "a rejected host yields no name (input %q)", in)
	}
}

func TestExtractSubdomainAcceptsExactlyOneLabel(t *testing.T) {
	e := New(Options{Domain: "example.com", Registry: registry.New()})
	for host, want := range map[string]string{
		"abc.example.com":          "abc",
		"a-1.example.com":          "a-1",
		"a.b.example.com":          "",
		"a.b.c.example.com":        "",
		"example.com":              "",
		".example.com":             "", // no label at all in front of the domain
		"abcexample.com":           "",
		"abc.example.com.evil.com": "",
		"abc.example.org":          "",
		"example.com.example.com":  "",
		"com":                      "",
	} {
		require.Equal(t, want, e.extractSubdomain(host), "host %q", host)
	}
}

func TestConfiguredDomainIsNormalised(t *testing.T) {
	e := New(Options{Domain: "Example.COM.", Registry: registry.New()})
	require.Equal(t, "abc", e.extractSubdomain("abc.example.com"))
	require.Equal(t, "", e.extractSubdomain("a.b.example.com"))
}

// serve runs one request through the edge without a hijackable connection.
func serve(e *Edge, host string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = host
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w
}

func TestInvalidHostGets400(t *testing.T) {
	reg := registry.New()
	e := New(Options{Domain: "localhost", Registry: reg})
	sess := &scriptSession{id: "s1", streams: make(chan protocol.Stream, 1)}
	require.NoError(t, reg.RegisterHTTP("abc", sess))
	defer func() { require.Zero(t, sess.opens.Load(), "no stream is opened for an invalid host") }()

	for _, host := range []string{
		"abc_def.localhost", "[::1]:443", "abc..localhost", "127.0.0.1:8443", "0x7f000001", "abc.0x7f:443", "abc.localhost:99999",
		"abc.localhost:80:90", "-abc.localhost", "abc.localhost\u00a0", "",
	} {
		before := requestCount(t, "bad_host")
		w := serve(e, host)
		require.Equal(t, http.StatusBadRequest, w.Code, "host %q", host)
		require.Equal(t, "invalid host\n", w.Body.String(), "host %q", host)
		require.Equal(t, before+1, requestCount(t, "bad_host"), "host %q", host)
	}
}

func TestHostThatIsNotATunnelGets404(t *testing.T) {
	reg := registry.New()
	e := New(Options{Domain: "localhost", Registry: reg})
	sess := &scriptSession{id: "s1", streams: make(chan protocol.Stream, 1)}
	require.NoError(t, reg.RegisterHTTP("abc", sess))

	for host, body := range map[string]string{
		"localhost":              "404 page not found\n",
		"x.abc.localhost":        "404 page not found\n",
		"abc.localhost.evil.com": "404 page not found\n",
		"abclocalhost":           "404 page not found\n",
		"nope.localhost":         "no tunnel for nope\n",
		"NOPE.localhost.:443":    "no tunnel for nope\n",
	} {
		before := requestCount(t, "not_found")
		w := serve(e, host)
		require.Equal(t, http.StatusNotFound, w.Code, "host %q", host)
		require.Equal(t, body, w.Body.String(), "host %q", host)
		require.Equal(t, before+1, requestCount(t, "not_found"), "host %q", host)
	}
	require.Zero(t, sess.opens.Load(), "no stream is opened for a host that is not a tunnel")
}

func TestConnectionThatCannotBeHijackedHoldsNothing(t *testing.T) {
	reg := registry.New()
	e := New(Options{Domain: "localhost", Registry: reg})
	sess := &scriptSession{id: "s1", streams: make(chan protocol.Stream, 1)}
	require.NoError(t, reg.RegisterHTTP("abc", sess))

	w := serve(e, "ABC.localhost.:443") // routed to the tunnel, but a recorder cannot be hijacked
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Zero(t, sess.opens.Load())
	require.Zero(t, e.limiter.Total())
}
