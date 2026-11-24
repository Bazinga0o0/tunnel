// Package edgehttp implements the public HTTPS edge that routes requests
// to the correct tunnel session by Host header.
package edgehttp

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// Defaults of the settings in Options.
const (
	DefaultMaxConnsPerTunnel = 256
	DefaultMaxConnsPerIP     = 64
	// DefaultMaxConns is the same as edgetcp.DefaultMaxConns, sized by
	// edgetcp.ConnMemoryBytes.
	DefaultMaxConns       = 1000
	DefaultIdleTimeout    = 5 * time.Minute
	DefaultMaxHeaderBytes = 64 << 10
)

type TunnelOpener interface {
	registry.Session
	OpenStream() (protocol.Stream, error)
}

// Options configures an Edge. The limits and the timeout share one
// convention: zero selects the default, a negative value disables the
// setting. MaxHeaderBytes is the one exception: it cannot be disabled.
type Options struct {
	Domain   string
	Registry *registry.Registry
	Logger   *slog.Logger

	// MaxConnsPerTunnel bounds the open visitor connections of one tunnel.
	// Default 256, a quarter of DefaultMaxConns.
	MaxConnsPerTunnel int
	// MaxConnsPerIP bounds the open visitor connections that one source IP
	// (for IPv6: one /64) holds to one tunnel. Default 64.
	MaxConnsPerIP int
	// MaxConns bounds the open visitor connections over all tunnels.
	// Default 1000. A connection counts until its tunnel stream is gone,
	// which can be later than the visitor (see edgetcp.ConnMemoryBytes);
	// the per-tunnel and per-IP limits count it the same way.
	MaxConns int
	// TotalBudget, when set, is a total that this Edge shares with other
	// edges (see edgeguard.Budget): a connection needs a slot in the budget
	// in addition to the limits above. Nil leaves the Edge with MaxConns
	// alone.
	TotalBudget *edgeguard.Budget
	// IdleTimeout closes a visitor connection on which no byte has moved in
	// either direction for this long. It also bounds how long the edge
	// waits for the next part of a request body, for the backend's answer to
	// a request to switch protocols, and for the answers that the backend
	// still owes after the edge refused a request. Default 5 minutes.
	//
	// With the timeout disabled (negative) nothing bounds those waits: a
	// backend that never answers a request to switch protocols, or never
	// ends its stream after a refused request, holds the connection and its
	// slot in the limits until the backend answers or ends its stream, or
	// the tunnel session ends. The visitor closing its connection does not
	// end the wait, because nothing reads from the visitor meanwhile.
	IdleTimeout time.Duration
	// MaxHeaderBytes bounds the head (request line and headers) of the
	// requests that follow the first one on a connection; the first is
	// bounded by the http.Server. Default 64 KiB. Values below 4096 are
	// raised to 4096. This limit cannot be disabled, because a request head
	// is held in memory as a whole: a negative value selects the default
	// like zero does.
	MaxHeaderBytes int
}

type Edge struct {
	opts    Options // resolved: defaults applied, a disabled setting is zero
	domain  string  // normalised Options.Domain
	logger  *slog.Logger
	limiter *edgeguard.Limiter

	// Warnings that a visitor or a tunnel client can cause at will go
	// through a limiter each.
	openWarn   *edgeguard.LogLimiter
	headerWarn *edgeguard.LogLimiter
	parseWarn  *edgeguard.LogLimiter
	endLog     *edgeguard.LogLimiter
}

// maxLogText bounds the error texts in log lines. The text of a parse error
// can carry a whole header line of the visitor.
const maxLogText = 256

func New(opts Options) *Edge {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	opts.MaxConnsPerTunnel = edgeguard.Resolve(opts.MaxConnsPerTunnel, DefaultMaxConnsPerTunnel)
	opts.MaxConnsPerIP = edgeguard.Resolve(opts.MaxConnsPerIP, DefaultMaxConnsPerIP)
	opts.MaxConns = edgeguard.Resolve(opts.MaxConns, DefaultMaxConns)
	opts.IdleTimeout = edgeguard.Resolve(opts.IdleTimeout, DefaultIdleTimeout)
	if opts.MaxHeaderBytes <= 0 { // not Resolve: this limit has no "disabled"
		opts.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if opts.MaxHeaderBytes < readBufferSize {
		opts.MaxHeaderBytes = readBufferSize
	}
	domain, ok := NormalizeHost(opts.Domain)
	if !ok {
		domain = strings.ToLower(opts.Domain)
	}
	e := &Edge{
		opts:    opts,
		domain:  domain,
		logger:  opts.Logger,
		limiter: edgeguard.NewLimiter(opts.MaxConns, opts.MaxConnsPerTunnel, opts.MaxConnsPerIP),

		openWarn:   edgeguard.NewLogLimiter(edgeguard.LogInterval),
		headerWarn: edgeguard.NewLogLimiter(edgeguard.LogInterval),
		parseWarn:  edgeguard.NewLogLimiter(edgeguard.LogInterval),
		endLog:     edgeguard.NewLogLimiter(edgeguard.LogInterval),
	}
	e.limiter.SetBudget(opts.TotalBudget)
	return e
}

// warn logs a warning through a limiter.
func (e *Edge) warn(limiter *edgeguard.LogLimiter, msg string, err error) {
	if ok, suppressed := limiter.Allow(); ok {
		e.logger.Warn(msg, "err", errText(err), "suppressed", suppressed)
	}
}

// logEnd notes at debug level why the edge ended a connection. A visitor can
// cause this line at will, so it goes through a limiter like the warnings.
func (e *Edge) logEnd(host string, err error) {
	if ok, suppressed := e.endLog.Allow(); ok {
		e.logger.Debug("connection ended", "host", host, "err", errText(err), "suppressed", suppressed)
	}
}

// errText returns the text of err for a log line, cut to maxLogText bytes.
func errText(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) > maxLogText {
		text = strings.ToValidUTF8(text[:maxLogText], "")
	}
	return text
}

// ServeHTTP implements http.Handler. For host == <subdomain>.<domain> it
// opens a yamux stream, hijacks the connection and forwards the request and
// every request that follows on the connection, each with the forwarding
// headers set from the connection. The backend's bytes are copied to the
// visitor as they are. The connection stops being HTTP only when the backend
// agrees to it in its answer to the first request (see switch.go). It answers
// 400 for a host that is not a host name, 404 for a host that is not a
// tunnel, 503 when a connection limit is reached and 502 when the tunnel
// cannot take the stream.
//
// Every answer the edge writes itself, without hijacking the connection, is
// the last one of its connection (see LastAnswer).
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	answered := LastAnswer(w)
	hijacked := false
	defer func() {
		if !hijacked {
			answered()
		}
	}()

	host, ok := NormalizeHost(r.Host)
	if !ok {
		metrics.RequestTotal.WithLabelValues("http", "bad_host").Inc()
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	sub := e.extractSubdomain(host)
	if sub == "" {
		metrics.RequestTotal.WithLabelValues("http", "not_found").Inc()
		http.NotFound(w, r)
		return
	}
	sess, ok := e.opts.Registry.LookupHTTP(sub)
	if !ok {
		metrics.RequestTotal.WithLabelValues("http", "not_found").Inc()
		http.Error(w, "no tunnel for "+sub, http.StatusNotFound)
		return
	}
	opener, ok := sess.(TunnelOpener)
	if !ok {
		http.Error(w, "session cannot open streams", http.StatusInternalServerError)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}

	// The request is parsed a second time, from its head as net/http read
	// it, by the code that also parses the requests that follow on the
	// connection. Until the connection is hijacked the reader holds nothing
	// but that head.
	src := &switchReader{r: bytes.NewReader(firstRequestHead(r))}
	br := bufio.NewReaderSize(src, readBufferSize)
	req, err := http.ReadRequest(br)
	if h, ok := NormalizeHost(hostOf(req)); err != nil || !ok || h != host {
		e.warn(e.parseWarn, "request head cannot be parsed again", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// What the edge knows about the visitor comes from the connection alone.
	// A remote address that cannot be parsed counts as one source of its own.
	source := edgeguard.ParseSource(r.RemoteAddr)
	fwd := forwarded{remoteIP: edgeguard.SourceIP(source), scheme: "http", host: host}
	if r.TLS != nil {
		fwd.scheme = "https"
	}

	// A first request that asks to switch protocols makes the response side
	// read the backend's answer and report the outcome on this channel. An
	// upgrade to h2c is taken out first: it is never passed on.
	dropH2C(req.Header)
	upgrade, connect := asksForUpgrade(req), req.Method == http.MethodConnect
	var decision chan bool
	if upgrade || connect {
		decision = make(chan bool, 1) // buffered: the response side never waits for the request side
	}

	slot, err := e.limiter.Take(sub, source)
	if err != nil {
		metrics.RequestTotal.WithLabelValues("http", edgeguard.LimitLabel(err)).Inc()
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	defer slot.Release()

	// Open the yamux stream BEFORE hijacking — errors here can still
	// produce a normal HTTP response.
	raw, err := opener.OpenStream()
	if err != nil {
		e.warn(e.openWarn, "open stream failed", err)
		http.Error(w, "tunnel stream error", http.StatusBadGateway)
		return
	}
	// Idle timeout and teardown need a stream that takes deadlines. One that
	// does not is refused instead of being used without them.
	stream, err := edgeguard.RequireDeadlines(raw)
	if err != nil {
		metrics.RequestTotal.WithLabelValues("http", "stream_rejected").Inc()
		e.warn(e.openWarn, "tunnel stream refused", err)
		http.Error(w, "tunnel stream error", http.StatusBadGateway)
		return
	}
	// Once the handler returns, the answer copy has returned on every path
	// and nothing reads the stream again. The stream keeps its place in the
	// total until it is gone from the session, drained at a pace meanwhile
	// (see edgeguard.RetirePaced); the visitor holds the place here, so the
	// hold cannot fail.
	streamDone, _ := slot.Hold()
	defer edgeguard.RetirePaced(stream, streamDone, e.logger)

	conn, buf, err := hj.Hijack()
	if err != nil {
		e.logger.Warn("hijack failed", "err", err)
		return
	}
	hijacked = true
	defer conn.Close()

	// From here on every read and write on either side moves the idle
	// deadline of both.
	idle := edgeguard.NewIdle(e.opts.IdleTimeout, conn, stream)
	idle.Touch()
	backend := &writeNote{w: idle.Writer(stream)}

	hdr := &protocol.StreamHeader{
		StreamType:   protocol.StreamTypeHTTP,
		OriginalHost: host,
		RemoteIP:     fwd.remoteIP,
		Scheme:       fwd.scheme,
	}
	if err := protocol.WriteStreamHeader(backend, hdr); err != nil {
		e.warn(e.headerWarn, "write header failed", err)
		return
	}

	abort := func() {
		_ = conn.Close()
		edgeguard.Abort(stream)
	}

	done := make(chan struct{})
	go func() { // backend -> visitor: the bytes as they are
		defer close(done)
		if decision != nil {
			// Whatever ends this goroutine (the end of the stream, the idle
			// timeout, an abort, a panic) releases a request side that
			// waits for the decision.
			defer close(decision)
		}
		defer edgeguard.Recover(e.logger, "http response copy", "host", host)
		clean := false
		defer func() {
			if !clean {
				abort()
			}
		}()
		if err := copyAnswers(idle.Writer(conn), idle.Reader(stream), decision, upgrade, connect); err == nil {
			clean = true
			if cw, ok := conn.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}
	}()
	// A panic of the request side must not let the stream be retired while
	// the response copy may still close it: a Close still under way when
	// the drain sees the stream end would give its slot back with the stream
	// in the session (edgeguard.RetirePaced). So end the response copy, wait
	// for it, and let the panic go on.
	defer func() {
		if r := recover(); r != nil {
			abort()
			<-done
			panic(r)
		}
	}()

	// visitor -> backend: request by request. The body of the first request
	// and everything after it is read from the hijacked connection through
	// buf.Reader, which holds what net/http had read past the head. r.Body
	// is not touched.
	visitor := &readNote{r: idle.Reader(buf.Reader)}
	limit := &headLimit{r: visitor}
	src.r = limit
	err = e.forwardRequests(br, limit, backend, req, host, fwd, decision)
	refused := false
	switch {
	case err == nil:
		_ = stream.Close() // the visitor is done sending; the backend may still answer
	case visitor.failed || backend.failed || errors.Is(err, errNoDecision):
		// One of the two sides is gone. There is nothing left to wait for.
		e.logEnd(host, err)
		abort()
	default:
		// The edge refuses to forward what the visitor sent: a request for
		// another host, a malformed or oversized one, CONNECT in the wrong
		// place. That ends the visitor's side of the connection only. The
		// backend may still owe answers to the requests before it, so the
		// stream is half-closed and the response side runs on until the
		// backend ends the stream, or the idle timeout does.
		e.logEnd(host, err)
		_ = stream.Close()
		refused = true
	}
	<-done
	if refused {
		drainVisitor(conn)
	}
}

// LastAnswer prepares w for an answer after which net/http closes the
// connection, and returns the function to call once the handler has written
// that answer. Handlers on the tunnel path call it for every answer they
// write without hijacking the connection.
//
// The public server bounds a connection only up to the end of a request head
// (ReadHeaderTimeout) and between requests (IdleTimeout); it has no read or
// write timeout, because hijacked tunnel connections live as long as their
// tunnel. A request that announces a body and does not send it would make
// net/http wait for that body without any deadline, before the answer to keep
// the connection, and after it to discard the rest. So LastAnswer sets
// "Connection: close" before the answer, which keeps net/http from reading
// the body before writing, and the returned function sets a read deadline in
// the past, which ends the read after writing at once. net/http then closes
// the connection, with its usual short pause after half-closing it so that
// the visitor receives the answer.
func LastAnswer(w http.ResponseWriter) (answered func()) {
	w.Header().Set("Connection", "close")
	return func() {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
	}
}

// Bounds of what the edge still reads from a visitor whose request it has
// refused, before it closes the connection.
const (
	drainBytes   = 256 << 10
	drainTimeout = 500 * time.Millisecond
)

// drainVisitor prepares a visitor connection for being closed after the edge
// stopped reading in the middle of what the visitor sent: the rest of an
// oversized head, of a malformed body. Closing a connection with unread bytes
// makes the system send a reset instead of an orderly end, and a reset can
// destroy what the visitor has not read yet, which here is the answer that
// the edge has just delivered. So the edge ends its sending side, then reads
// and discards what the visitor still sends, within bounds. The caller closes
// the connection afterwards.
func drainVisitor(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(drainTimeout))
	_, _ = io.CopyN(io.Discard, conn, drainBytes)
}

// hostOf returns the host of req, or "" when there is no request.
func hostOf(req *http.Request) string {
	if req == nil {
		return ""
	}
	return req.Host
}
