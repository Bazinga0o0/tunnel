package main

import (
	"crypto/tls"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
	"github.com/Bazinga0o0/tunnel/internal/server/edgehttp"
	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
)

// newPublicServer builds the public HTTPS server (listen.http_addr). It has
// no ReadTimeout or WriteTimeout: HTTP tunnel requests are hijacked and live
// as long as their tunnel. Web UI requests get their deadlines in
// dispatchHost instead.
func newPublicServer(handler http.Handler, s config.HTTPServer, logger *slog.Logger) *http.Server {
	s = s.Resolved()
	return &http.Server{
		Handler: handler,
		// Also bounds the TLS handshake: net/http derives its deadline from
		// the smallest of the read and write timeouts.
		ReadHeaderTimeout: s.ReadHeaderTimeout,
		IdleTimeout:       s.IdleTimeout,
		MaxHeaderBytes:    s.MaxHeaderBytes,
		// net/http writes one line per failed TLS handshake or bad request,
		// which anybody can cause at will.
		ErrorLog: rateLimitedErrorLog(logger, "public https server"),
	}
}

// rateLimitedErrorLog returns a log.Logger for http.Server.ErrorLog that
// passes at most one line per edgeguard.LogInterval to logger, with the
// number of lines held back. Panics of handlers ("http: panic serving")
// have a limiter of their own and are logged as errors, so that a flood of
// handshake errors cannot hide them.
func rateLimitedErrorLog(logger *slog.Logger, source string) *log.Logger {
	return log.New(&limitedLogWriter{
		logger: logger,
		source: source,
		limit:  edgeguard.NewLogLimiter(edgeguard.LogInterval),
		panics: edgeguard.NewLogLimiter(edgeguard.LogInterval),
	}, "", 0)
}

type limitedLogWriter struct {
	logger *slog.Logger
	source string
	limit  *edgeguard.LogLimiter // everything but panics
	panics *edgeguard.LogLimiter
}

func (w *limitedLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if strings.HasPrefix(line, "http: panic serving") {
		if ok, suppressed := w.panics.Allow(); ok {
			w.logger.Error(w.source+": "+line, "suppressed", suppressed)
		}
		return len(p), nil
	}
	if ok, suppressed := w.limit.Allow(); ok {
		w.logger.Warn(w.source+": "+line, "suppressed", suppressed)
	}
	return len(p), nil
}

// dispatchHost routes requests by Host header. The apex domain and
// "app.<domain>" go to the frontend when it is not nil; the hosts of the
// registered services (keys of services: the full host, such as
// "myservice.<domain>") go to their proxy; everything else goes to the
// tunnel edge. A service comes before the tunnels: a tunnel or reservation
// of its subdomain from before the service was added does not take its
// requests. The host is normalised once, with the same function the edge
// uses; a request whose host is not a valid host name gets 400.
//
// Frontend requests get the read and write deadlines of s; a service proxy
// sets its own. Tunnel requests run without: the edge hijacks the
// connection and keeps its own idle timeout. Nothing carries over from one
// request of a connection to the next: net/http sets the read deadline anew
// for every request and clears the write deadline after each one, and a
// hijack clears both.
//
// An answer on the tunnel path that is not hijacked, the 400 here and the
// edge's own refusals, is the last one of its connection
// (edgehttp.LastAnswer): nothing else would bound the wait for a request body
// that never arrives. Web UI answers keep the connection, and so do the
// answers of a service, but for the proxy's refusals before the body.
func dispatchHost(domain string, frontend, tunnel http.Handler, services map[string]http.Handler, s config.HTTPServer) http.Handler {
	apex, ok := edgehttp.NormalizeHost(domain)
	if !ok {
		apex = strings.ToLower(domain)
	}
	app := "app." + apex
	s = s.Resolved()
	byHost := make(map[string]http.Handler, len(services))
	for host, h := range services {
		if normal, ok := edgehttp.NormalizeHost(host); ok {
			host = normal
		}
		byHost[host] = h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, ok := edgehttp.NormalizeHost(r.Host)
		if !ok {
			answered := edgehttp.LastAnswer(w)
			http.Error(w, "invalid host", http.StatusBadRequest)
			answered()
			return
		}
		if frontend != nil && (host == apex || host == app) {
			rc := http.NewResponseController(w)
			now := time.Now()
			// The read deadline covers reading the body and ends with it. When
			// a read fails, net/http cancels the request context, and after
			// the body (at once for a request without one) it keeps a read
			// pending to notice a client that goes away: a deadline left in
			// place would cancel the handler's work.
			if s.FrontendReadTimeout > 0 && hasBody(r) {
				_ = rc.SetReadDeadline(now.Add(s.FrontendReadTimeout))
				r.Body = &readDeadlineBody{ReadCloser: r.Body, clear: func() { _ = rc.SetReadDeadline(time.Time{}) }}
			}
			if s.FrontendWriteTimeout > 0 {
				_ = rc.SetWriteDeadline(now.Add(s.FrontendWriteTimeout))
			}
			frontend.ServeHTTP(w, r)
			return
		}
		if service, ok := byHost[host]; ok {
			service.ServeHTTP(w, r)
			return
		}
		tunnel.ServeHTTP(w, r)
	})
}

// hasBody reports whether the request announces a body.
func hasBody(r *http.Request) bool {
	return r.Body != nil && r.Body != http.NoBody && (r.ContentLength != 0 || len(r.TransferEncoding) > 0)
}

// readDeadlineBody clears the read deadline when the body has been read to
// its end or a read has failed.
type readDeadlineBody struct {
	io.ReadCloser
	once  sync.Once
	clear func()
}

func (b *readDeadlineBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.clear)
	}
	return n, err
}

// listenPublic opens the public HTTPS listener: TCP, limited in its
// connections, then TLS. The limit sits below TLS so that a refused
// connection costs no handshake.
func listenPublic(addr string, tlsConfig *tls.Config, s config.HTTPServer, logger *slog.Logger) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(limitPublicListener(ln, s, logger), tlsConfig), nil
}

// limitPublicListener wraps ln with the connection limits of s, or returns
// it unchanged when both are disabled.
func limitPublicListener(ln net.Listener, s config.HTTPServer, logger *slog.Logger) net.Listener {
	s = s.Resolved()
	if s.MaxConns <= 0 && s.MaxConnsPerIP <= 0 {
		return ln
	}
	return &limitListener{
		Listener: ln,
		limiter:  edgeguard.NewLimiter(s.MaxConns, 0, s.MaxConnsPerIP),
		logger:   logger,
		refused:  edgeguard.NewLogLimiter(edgeguard.LogInterval),
	}
}

// limitListener closes accepted connections beyond a total and a per-source
// limit (IPv4 address or IPv6 /64) right away, before any byte is read.
type limitListener struct {
	net.Listener
	limiter *edgeguard.Limiter // total, and per source under the key ""
	logger  *slog.Logger
	refused *edgeguard.LogLimiter
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		release, err := l.limiter.Acquire("", edgeguard.ParseSource(conn.RemoteAddr().String()))
		if err != nil {
			_ = conn.Close()
			label := edgeguard.LimitLabel(err)
			metrics.RequestTotal.WithLabelValues("https", label).Inc()
			if ok, suppressed := l.refused.Allow(); ok {
				l.logger.Warn("public https listener: connection limit reached, closing new connections",
					"limit", label, "remote", conn.RemoteAddr().String(), "suppressed", suppressed)
			}
			continue
		}
		return &limitedConn{Conn: conn, release: release}, nil
	}
}

// limitedConn gives its slot back on the first Close.
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
