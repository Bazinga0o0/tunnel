package edgetcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
)

// Defaults of the settings in Options.
const (
	DefaultMaxConnsPerTunnel = 256
	DefaultMaxConnsPerIP     = 64
	// DefaultMaxConns is also the default of edge.max_conns, the total the
	// TCP and the HTTP edge share. At ConnMemoryBytes per connection it
	// bounds the edges to about 690 MiB (see cmd/tunneld/memory.go for the
	// whole budget).
	DefaultMaxConns    = 1000
	DefaultIdleTimeout = 30 * time.Minute
)

// ConnMemoryBytes is the most memory one visitor connection of the TCP or
// the HTTP edge makes the server hold, its tunnel stream included: the
// stream's receive buffer when the visitor does not read and the tunnel
// client writes as fast as it can (up to about twice
// protocol.StreamWindowBytes), the copy buffers and goroutines of the edge,
// and for HTTP the TLS connection and a follow-up request head being read.
// Measured (cmd/tunneld/memory_measure_test.go, go1.27.4): 595 KiB for TCP,
// 602 KiB for HTTP, plus up to 1.5 × http_server.max_header_bytes for a
// request head; rounded up to 704 KiB.
//
// A stream that the edge is done with and the tunnel client keeps open
// keeps its slot of the total until it is gone, and is drained at a pace
// meanwhile (edgeguard.RetirePaced): its drain goroutine and buffer, and what
// the client has sent and the drain not yet read, at most a window, which
// yamux's buffer growth can make take up to about twice the window. That is
// within this constant. Measured with a client that keeps writing as fast as
// it can (two runs, 200 streams each): 83 and 249 KiB per stream for TCP,
// 284 and 136 KiB for HTTP; the largest buffer the edgeguard tests saw was
// 520 KiB.
const ConnMemoryBytes = 704 << 10

// ListenerMemoryBytes is the memory counted for one TCP tunnel port: its
// listener and its accept loop. Measured (memory_measure_test.go, go1.27.4):
// a session that holds a TCP port did not cost more than one without, within
// the noise of a few KiB; counted at one goroutine and the listener, 16 KiB.
const ListenerMemoryBytes = 16 << 10

// TunnelOpener mirrors the edgehttp interface — any session that can open
// yamux streams against a registered tunnel client.
type TunnelOpener interface {
	OpenStream() (protocol.Stream, error)
}

// Options configures a Manager. The limits and the timeout share one
// convention: zero selects the default, a negative value disables the
// setting.
type Options struct {
	Pool   *Pool
	Logger *slog.Logger

	// BindHost is the local address the tunnel listeners bind to. Empty means
	// all interfaces. Anything else must be an IP address literal such as
	// "127.0.0.1" or "::1"; host names are not resolved, and Open fails for
	// every other value.
	BindHost string

	// MaxConnsPerTunnel bounds the open connections of one tunnel port.
	// Default 256, a quarter of DefaultMaxConns.
	MaxConnsPerTunnel int
	// MaxConnsPerIP bounds the open connections that one source IP (for
	// IPv6: one /64) holds on one tunnel port. Default 64.
	MaxConnsPerIP int
	// MaxConns bounds the open connections over all ports of the Manager.
	// Default 1000. A connection counts until its tunnel stream is gone,
	// which can be later than the visitor (see ConnMemoryBytes); the
	// per-tunnel and per-IP limits count it the same way.
	MaxConns int
	// TotalBudget, when set, is a total that this Manager shares with other
	// edges (see edgeguard.Budget): a connection needs a slot in the budget
	// in addition to the limits above. Nil leaves the Manager with MaxConns
	// alone.
	TotalBudget *edgeguard.Budget
	// IdleTimeout closes a connection on which no byte has moved in either
	// direction for this long. Default 30 minutes.
	//
	// With the timeout disabled (negative) nothing bounds the time a silent
	// connection is kept: one whose visitor has finished sending waits for
	// the backend to end its side, and holds its slot in the limits until
	// then.
	IdleTimeout time.Duration
}

// Manager accepts TCP connections on dynamically-allocated listeners and
// pipes them through per-connection yamux streams.
type Manager struct {
	opts    Options // resolved: defaults applied, a disabled setting is zero
	bindErr error   // set when Options.BindHost is not an IP address
	pool    *Pool
	logger  *slog.Logger
	limiter *edgeguard.Limiter
	listen  func(port int) (net.Listener, error)
	mu      sync.Mutex
	byPort  map[int]*activeListener
}

type activeListener struct {
	port       int
	key        string // port as limiter key
	listener   net.Listener
	session    TunnelOpener
	cancel     context.CancelFunc
	acceptWarn *edgeguard.LogLimiter
	openWarn   *edgeguard.LogLimiter
	panicLog   *edgeguard.LogLimiter // panics of the accept loop

	mu     sync.Mutex
	closed bool // set by Close; no connection is tracked afterwards
	conns  map[net.Conn]struct{}
}

// New builds a TCP edge manager with the default limits.
func New(pool *Pool, logger *slog.Logger) *Manager {
	return NewWithOptions(Options{Pool: pool, Logger: logger})
}

// NewWithOptions builds a TCP edge manager.
func NewWithOptions(opts Options) *Manager {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	opts.MaxConnsPerTunnel = edgeguard.Resolve(opts.MaxConnsPerTunnel, DefaultMaxConnsPerTunnel)
	opts.MaxConnsPerIP = edgeguard.Resolve(opts.MaxConnsPerIP, DefaultMaxConnsPerIP)
	opts.MaxConns = edgeguard.Resolve(opts.MaxConns, DefaultMaxConns)
	opts.IdleTimeout = edgeguard.Resolve(opts.IdleTimeout, DefaultIdleTimeout)
	m := &Manager{
		opts:    opts,
		pool:    opts.Pool,
		logger:  opts.Logger,
		limiter: edgeguard.NewLimiter(opts.MaxConns, opts.MaxConnsPerTunnel, opts.MaxConnsPerIP),
		byPort:  map[int]*activeListener{},
	}
	m.limiter.SetBudget(opts.TotalBudget)
	if opts.BindHost != "" {
		if _, err := netip.ParseAddr(opts.BindHost); err != nil {
			m.bindErr = fmt.Errorf("edgetcp: BindHost %q is not an IP address", opts.BindHost)
		}
	}
	m.listen = func(port int) (net.Listener, error) {
		return net.Listen("tcp", listenAddress(opts.BindHost, port))
	}
	return m
}

// listenAddress returns the address a tunnel listener binds to. An empty
// host is the wildcard address.
func listenAddress(bindHost string, port int) string {
	return net.JoinHostPort(bindHost, strconv.Itoa(port))
}

// Open allocates a port, opens a listener, and starts forwarding to session.
// Returns the allocated port or an error.
func (m *Manager) Open(ctx context.Context, preferred int, session TunnelOpener) (int, error) {
	if m.bindErr != nil {
		return 0, m.bindErr
	}
	port, err := m.pool.Allocate(preferred)
	if err != nil {
		return 0, err
	}
	ln, err := m.listen(port)
	if err != nil {
		m.pool.Release(port)
		return 0, err
	}

	runCtx, cancel := context.WithCancel(ctx)
	al := &activeListener{
		port:       port,
		key:        strconv.Itoa(port),
		listener:   ln,
		session:    session,
		cancel:     cancel,
		acceptWarn: edgeguard.NewLogLimiter(edgeguard.LogInterval),
		openWarn:   edgeguard.NewLogLimiter(edgeguard.LogInterval),
		panicLog:   edgeguard.NewLogLimiter(edgeguard.LogInterval),
		conns:      map[net.Conn]struct{}{},
	}
	m.mu.Lock()
	m.byPort[port] = al
	m.mu.Unlock()

	go m.acceptLoop(runCtx, al)
	m.logger.Info("tcp tunnel listener opened", "port", port)
	return port, nil
}

// Close stops the listener on port (if any), closes the connections that
// were accepted on it and returns the port to the pool. Safe to call for
// ports that aren't currently open.
func (m *Manager) Close(port int) {
	m.mu.Lock()
	al, ok := m.byPort[port]
	if ok {
		delete(m.byPort, port)
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	al.cancel()
	_ = al.listener.Close()
	for _, conn := range al.close() {
		_ = conn.Close()
	}
	m.pool.Release(port)
	m.logger.Info("tcp tunnel listener closed", "port", port)
}

// acceptLoop accepts connections until the listener is closed. A panic at
// loop level does not end it: the port would stay bound with nobody
// accepting on it. The loop is entered again instead, after the pause of the
// backoff, so that a panic that repeats does not spin.
func (m *Manager) acceptLoop(ctx context.Context, al *activeListener) {
	var backoff edgeguard.Backoff
	for m.acceptConns(ctx, al, &backoff) {
		if !backoff.Sleep(ctx) {
			return
		}
	}
}

// acceptConns is the accept loop proper. It returns true when a panic ended
// it and false when the listener was closed.
//
// The panic is logged with its stack through a limiter: a successful Accept
// resets the backoff, so panics that alternate with successes could otherwise
// write a stack every few milliseconds.
func (m *Manager) acceptConns(ctx context.Context, al *activeListener, backoff *edgeguard.Backoff) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			if ok, suppressed := al.panicLog.Allow(); ok {
				edgeguard.LogPanic(m.logger, r, "tcp accept loop", "port", al.port, "suppressed", suppressed)
			}
			panicked = true
		}
	}()
	for {
		conn, err := al.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if ok, suppressed := al.acceptWarn.Allow(); ok {
				m.logger.Warn("tcp accept failed", "port", al.port, "err", err, "suppressed", suppressed)
			}
			if !backoff.Sleep(ctx) {
				return
			}
			continue
		}
		backoff.Reset()
		go m.handleConn(al, conn)
	}
}

func (m *Manager) handleConn(al *activeListener, conn net.Conn) {
	defer edgeguard.Recover(m.logger, "tcp connection", "port", al.port)
	defer conn.Close()

	// A connection over a limit is closed without a stream. A remote address
	// that cannot be parsed counts as one source of its own.
	source := edgeguard.ParseSource(conn.RemoteAddr().String())
	slot, err := m.limiter.Take(al.key, source)
	if err != nil {
		metrics.RequestTotal.WithLabelValues("tcp", edgeguard.LimitLabel(err)).Inc()
		return
	}
	defer slot.Release()
	if !al.track(conn) {
		return // the listener was closed while this connection was accepted
	}
	defer al.untrack(conn)

	metrics.RequestTotal.WithLabelValues("tcp", "proxied").Inc()

	raw, err := al.session.OpenStream()
	if err != nil {
		if ok, suppressed := al.openWarn.Allow(); ok {
			m.logger.Warn("open stream failed", "port", al.port, "err", err, "suppressed", suppressed)
		}
		return
	}
	// Idle timeout and teardown need a stream that takes deadlines. One that
	// does not is refused instead of being used without them.
	stream, err := edgeguard.RequireDeadlines(raw)
	if err != nil {
		metrics.RequestTotal.WithLabelValues("tcp", "stream_rejected").Inc()
		if ok, suppressed := al.openWarn.Allow(); ok {
			m.logger.Warn("tunnel stream refused", "port", al.port, "err", err, "suppressed", suppressed)
		}
		return
	}
	// Once the handler returns, both copy directions have ended and nothing
	// reads the stream again. The stream keeps its place in the total until
	// it is gone from the session, drained at a pace meanwhile (see
	// edgeguard.RetirePaced); the visitor holds the place here, so the hold
	// cannot fail.
	streamDone, _ := slot.Hold()
	defer edgeguard.RetirePaced(stream, streamDone, m.logger)
	if al.isClosed() {
		return // closed while the stream was being opened
	}

	idle := edgeguard.NewIdle(m.opts.IdleTimeout, conn, stream)
	idle.Touch()

	hdr := &protocol.StreamHeader{
		StreamType: protocol.StreamTypeTCP,
		RemoteIP:   edgeguard.SourceIP(source),
		PublicPort: al.port,
	}
	if err := protocol.WriteStreamHeader(idle.Writer(stream), hdr); err != nil {
		return
	}
	m.pipe(al, conn, stream, idle)
}

// pipe copies in both directions until both are done. A direction that ends
// cleanly is passed on as a half-close and the other one goes on. A direction
// that ends with an error (reset, idle timeout, dead stream) ends the whole
// connection.
func (m *Manager) pipe(al *activeListener, conn net.Conn, stream edgeguard.Stream, idle *edgeguard.Idle) {
	abort := func() {
		_ = conn.Close()
		edgeguard.Abort(stream)
	}

	done := make(chan struct{})
	go func() { // backend -> visitor
		defer close(done)
		defer edgeguard.Recover(m.logger, "tcp connection reply copy", "port", al.port)
		clean := false
		defer func() {
			if !clean {
				abort()
			}
		}()
		if _, err := io.Copy(idle.Writer(conn), idle.Reader(stream)); err == nil {
			clean = true
			if cw, ok := conn.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}
	}()
	// A panic of this direction must not let the stream be retired while
	// the other direction may still close it: a Close still under way when
	// the drain sees the stream end would give its slot back with the stream
	// in the session (edgeguard.Retire). So end the other direction, wait
	// for it, and let the panic go on.
	defer func() {
		if r := recover(); r != nil {
			abort()
			<-done
			panic(r)
		}
	}()

	// visitor -> backend
	if _, err := io.Copy(idle.Writer(stream), idle.Reader(conn)); err != nil {
		abort()
	} else {
		_ = stream.Close() // the visitor is done sending; the backend may still answer
	}
	<-done
}

// track remembers an accepted connection so that Close can end it. It
// returns false when the listener is already closed.
func (al *activeListener) track(conn net.Conn) bool {
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.closed {
		return false
	}
	al.conns[conn] = struct{}{}
	return true
}

func (al *activeListener) untrack(conn net.Conn) {
	al.mu.Lock()
	delete(al.conns, conn)
	al.mu.Unlock()
}

func (al *activeListener) isClosed() bool {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.closed
}

// close marks the listener closed and returns the connections that were
// open at that moment.
func (al *activeListener) close() []net.Conn {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.closed = true
	conns := make([]net.Conn, 0, len(al.conns))
	for conn := range al.conns {
		conns = append(conns, conn)
	}
	return conns
}
