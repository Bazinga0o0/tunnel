package edgehttp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
)

// readBufferSize is the size of the buffer that requests are parsed from. It
// is also the smallest header limit that can be enforced to the byte.
const readBufferSize = 4096

var (
	errHeadTooLarge = errors.New("edgehttp: request header too large")
	errHostChanged  = errors.New("edgehttp: request for another host on the same connection")
	errBadHeader    = errors.New("edgehttp: invalid header field")
	errLateConnect  = errors.New("edgehttp: CONNECT is not the first request of the connection")
	errNoDecision   = errors.New("edgehttp: connection ended before the backend answered the request to switch protocols")
)

// forwarded holds what the edge knows about the visitor from the connection.
type forwarded struct {
	remoteIP string
	scheme   string
	host     string // normalised host of the connection's requests
}

// apply replaces the forwarding headers of req. Whatever the visitor sent
// under these names is dropped, including spellings with underscores that
// some backends treat as the same header, and including the ways to bring
// such a field in or out by the back door: as an announced trailer, or as a
// name in Connection that makes the next proxy drop the header again.
func (f forwarded) apply(req *http.Request) {
	for key := range req.Header {
		if isForwardingHeader(key) {
			delete(req.Header, key)
		}
	}
	dropForwardingTrailers(req)
	if values, ok := req.Header["Connection"]; ok {
		if values = withoutTokens(values, isForwardingHeader); len(values) > 0 {
			req.Header["Connection"] = values
		} else {
			delete(req.Header, "Connection")
		}
	}

	if f.remoteIP != "" { // unknown only when the server reports no usable peer address
		req.Header.Set("X-Forwarded-For", f.remoteIP)
	}
	req.Header.Set("X-Forwarded-Proto", f.scheme)
	req.Header.Set("X-Forwarded-Host", f.forwardedHost(req.Host))
	// Request.Write adds a Go User-Agent when the header is missing. An
	// empty entry keeps it from doing so and is not written itself.
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header["User-Agent"] = []string{""}
	}
}

// forwardedHost returns the value of X-Forwarded-Host for a request with the
// given Host header. It is the host in the form that the edge routes on, not
// in the visitor's spelling, followed by the port only when the header named
// one that is not the default port of the scheme.
func (f forwarded) forwardedHost(hostport string) string {
	port, ok := portOf(hostport)
	if !ok || (f.scheme == "https" && port == 443) || (f.scheme == "http" && port == 80) {
		return f.host
	}
	return f.host + ":" + strconv.Itoa(port)
}

// keepTarget makes Request.Write send an origin-form request target byte for
// byte as the visitor sent it. Written from the parsed URL, the path would be
// escaped anew ('"' becomes %22, for example). The target has passed the
// checks of http.ReadRequest either way, and the edge decides nothing by it.
//
// A target that starts with "//" cannot be carried this way (Request.Write
// would take it for an authority) and is written from the parsed URL, as are
// the absolute form and "*".
func keepTarget(req *http.Request) {
	if target := req.RequestURI; strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") {
		req.URL = &url.URL{Opaque: target}
	}
}

// isForwardingHeader reports whether key names a header by which a proxy
// tells the backend about the client, in any spelling: the ones the edge
// sets itself, and the client address headers that frameworks read (chi's
// RealIP takes True-Client-IP first, Rails reads Client-IP). The edge passes
// none of them on from the visitor.
func isForwardingHeader(key string) bool {
	switch strings.ToLower(strings.ReplaceAll(key, "_", "-")) {
	case "x-forwarded-for", "x-real-ip", "forwarded", "x-forwarded-proto", "x-forwarded-host",
		"true-client-ip", "x-client-ip", "client-ip":
		return true
	}
	return false
}

// dropForwardingTrailers removes the forwarding fields from the trailers of
// req: the announced ones before the request is written, the received ones
// once the body has been read to its end.
func dropForwardingTrailers(req *http.Request) {
	for key := range req.Trailer {
		if isForwardingHeader(key) {
			delete(req.Trailer, key)
		}
	}
}

// withoutTokens returns the values of a Connection header without the tokens
// that drop reports. Values that hold none of them are returned as they are.
func withoutTokens(values []string, drop func(token string) bool) []string {
	var out []string
	for _, v := range values {
		tokens := strings.Split(v, ",")
		kept := tokens[:0]
		for _, token := range tokens {
			if token = strings.TrimSpace(token); !drop(token) {
				kept = append(kept, token)
			}
		}
		switch {
		case len(kept) == len(tokens):
			out = append(out, v)
		case len(kept) > 0:
			out = append(out, strings.Join(kept, ", "))
		}
	}
	return out
}

// firstRequestHead renders the head of the request that net/http parsed
// before the connection was hijacked, so that the edge can parse it the same
// way as the requests that follow. The framing headers that net/http moved
// out of the header map are put back.
func firstRequestHead(r *http.Request) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/%d.%d\r\nHost: %s\r\n", r.Method, r.RequestURI, r.ProtoMajor, r.ProtoMinor, r.Host)
	_ = r.Header.Write(&b)
	if len(r.TransferEncoding) > 0 {
		fmt.Fprintf(&b, "Transfer-Encoding: %s\r\n", strings.Join(r.TransferEncoding, ", "))
	}
	if len(r.Trailer) > 0 {
		keys := make([]string, 0, len(r.Trailer))
		for k := range r.Trailer {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(&b, "Trailer: %s\r\n", strings.Join(keys, ", "))
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// forwardRequests writes req to the backend, then reads, checks and writes
// every request that follows on the connection, each with its forwarding
// headers replaced. br is the reader req was parsed from; bodies are read
// from it by Content-Length or chunked encoding.
//
// decision is nil unless req, the first request, asks to switch protocols
// (see switch.go). In that case nothing more is read from the visitor until
// the backend's answer is known: on true the rest of the connection is
// copied as raw bytes, on false the requests that follow are forwarded like
// those of any keep-alive connection. Requests after the first cannot switch
// protocols: their Upgrade is removed, and CONNECT ends the connection.
//
// It returns nil when the visitor ended the connection between two requests
// (or, after a switch, ended its side) and an error in every other case.
func (e *Edge) forwardRequests(br *bufio.Reader, limit *headLimit, backend io.Writer, req *http.Request, host string, fwd forwarded, decision <-chan bool) error {
	for first := true; ; first = false {
		if !validHeader(req.Header) {
			return errBadHeader
		}
		if !first {
			if req.Method == http.MethodConnect {
				return errLateConnect
			}
			dropH2C(req.Header) // the first request lost it before it got here
			dropUpgrade(req.Header)
		}
		fwd.apply(req)
		keepTarget(req)
		if req.Body != nil && req.Body != http.NoBody {
			req.Body = requestBody{Reader: req.Body, req: req}
		}

		if err := req.Write(backend); err != nil {
			return err
		}
		metrics.RequestTotal.WithLabelValues("http", "proxied").Inc()

		if first && decision != nil {
			// The response side closes the channel when it ends, whatever
			// ends it, so this wait is over with the idle timeout at the
			// latest.
			raw, ok := <-decision
			if !ok {
				return errNoDecision
			}
			if raw {
				_, err := io.Copy(backend, br)
				return err
			}
		}

		// The limit cannot be switched off: http.ReadRequest would read a
		// head of any size into memory.
		limit.arm(e.opts.MaxHeaderBytes - br.Buffered())
		next, err := http.ReadRequest(br)
		limit.disarm()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h, ok := NormalizeHost(next.Host); !ok || h != host {
			return errHostChanged
		}
		req = next
	}
}

// requestBody wraps the body that http.ReadRequest returned for req.
//
// Its Close does nothing. The wrapped body reads the rest of the body from
// the visitor when it is closed, and Request.Write closes it when the write
// to the backend fails: the edge would then wait for, and discard, a body
// that nobody is going to receive. After a successful write the body has
// been read to its end anyway; after a failed one the connection is torn
// down.
//
// At the end of a chunked body the wrapped body stores the trailer fields
// it received in req.Trailer, announced or not. They are filtered before
// Request.Write gets to write them.
type requestBody struct {
	io.Reader
	req *http.Request
}

func (b requestBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		dropForwardingTrailers(b.req)
	}
	return n, err
}

func (requestBody) Close() error { return nil }

// readNote and writeNote remember whether a read from the visitor or a write
// to the stream has failed. When the request direction ends with an error,
// that tells a side that is gone from a request that the edge refused. Each
// is used by one goroutine only.
type readNote struct {
	r      io.Reader
	failed bool
}

func (n *readNote) Read(p []byte) (int, error) {
	c, err := n.r.Read(p)
	if err != nil && err != io.EOF {
		n.failed = true
	}
	return c, err
}

type writeNote struct {
	w      io.Writer
	failed bool
}

func (n *writeNote) Write(p []byte) (int, error) {
	c, err := n.w.Write(p)
	if err != nil {
		n.failed = true
	}
	return c, err
}

// validHeader applies to the requests the edge parses itself what the
// net/http server applies to the first request of a connection: field names
// are tokens. http.ReadRequest accepts other names, for example with a space
// before the colon. (Control characters in values it rejects itself.)
func validHeader(h http.Header) bool {
	for key := range h {
		if !validFieldName(key) {
			return false
		}
	}
	return true
}

func validFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// switchReader lets the reader that requests are parsed from change its
// source: the rendered head of the first request before the connection is
// hijacked, the visitor afterwards.
type switchReader struct {
	r io.Reader
}

func (s *switchReader) Read(p []byte) (int, error) { return s.r.Read(p) }

// headLimit bounds the bytes that are read from the visitor while a request
// head is parsed. Bodies are read with the limit disarmed.
type headLimit struct {
	r      io.Reader
	armed  bool
	budget int
}

func (l *headLimit) arm(budget int) {
	l.armed = true
	l.budget = budget
}

func (l *headLimit) disarm() { l.armed = false }

func (l *headLimit) Read(p []byte) (int, error) {
	if !l.armed {
		return l.r.Read(p)
	}
	if l.budget <= 0 {
		return 0, errHeadTooLarge
	}
	if len(p) > l.budget {
		p = p[:l.budget]
	}
	n, err := l.r.Read(p)
	l.budget -= n
	return n, err
}
