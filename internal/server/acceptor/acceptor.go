// Package acceptor terminates TLS tunnel connections, runs the auth handshake,
// and services control messages over the first yamux stream.
package acceptor

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeudp"
	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
)

// TCPEdgeManager is the subset of edgetcp.Manager used by the acceptor.
// Defined as an interface so tests can supply fakes without real listeners.
type TCPEdgeManager interface {
	Open(ctx context.Context, preferred int, session edgetcp.TunnelOpener) (int, error)
	Close(port int)
}

// UDPEdgeManager is the subset of edgeudp.Manager used by the acceptor.
// Defined as an interface so tests can supply fakes without a real UDP listener.
type UDPEdgeManager interface {
	Open(ctx context.Context, preferred int, session edgeudp.TunnelOpener) (int, error)
	Close(port int)
}

// Options configures an Acceptor.
//
// Every limit below follows one convention: the zero value selects the
// default named on the field, a negative value disables the limit.
type Options struct {
	Domain       string
	Registry     *registry.Registry
	Verifier     *auth.TokenVerifier // P1-style static; used when DBVerifier is nil
	DBVerifier   *auth.DBVerifier    // overrides Verifier when set
	Reservations *reservations.Service
	TCPEdge      TCPEdgeManager // nil disables TCP tunneling
	UDPEdge      UDPEdgeManager // nil disables UDP tunneling
	Logger       *slog.Logger

	// ServerVersion is the version the server names in its HelloAck. Empty
	// sends no version.
	ServerVersion string

	// HandshakeTimeout is the time a connection has from accept until it
	// has received a successful HelloAck: TLS handshake, control stream and
	// hello all fall under it. Default 10 s.
	HandshakeTimeout time.Duration

	// VerifyTimeout bounds one call to the token verifier, and one
	// reservation lookup. A verifier that does not answer in time counts as
	// a rejected token, a lookup that does not as a refusal. Default 5 s.
	VerifyTimeout time.Duration

	// MaxUnauthConns is the number of connections that may be in the
	// handshake at the same time. Further connections are closed right after
	// accept. Default 256.
	MaxUnauthConns int

	// MaxUnauthConnsPerIP is the same limit per source: per IPv4 address or
	// per IPv6 /64. Default 16.
	MaxUnauthConnsPerIP int

	// MaxPreAuthFrameSize is the largest control frame accepted before the
	// client has authenticated (the hello), in bytes. Default 4 KiB. A
	// negative value leaves the protocol ceiling of 1 MiB, which no value
	// can exceed.
	MaxPreAuthFrameSize int

	// MaxControlFrameSize is the largest control frame accepted after
	// authentication, in bytes. Default 16 KiB. Negative: as above.
	MaxControlFrameSize int

	// AcceptBacklog is the yamux accept backlog of the server side, see
	// protocol.ServerOptions. Default 32. A negative value leaves yamux's own
	// default of 256. Apart from the control stream the client may not open
	// streams at all: the first extra stream closes the session.
	AcceptBacklog int

	// StreamCloseTimeout, when positive, replaces yamux's five minutes for
	// which a stream the server closed waits for the client's FIN (see
	// protocol.ServerOptions). It is not a configuration key: the memory
	// measurement (cmd/tunneld) shortens it.
	StreamCloseTimeout time.Duration

	// MaxStreamsPerSession is the number of data streams the server keeps
	// open on one session; TunnelSession.OpenStream fails beyond it.
	// Default 512.
	MaxStreamsPerSession int

	// MaxStreamsPerUser is the number of data streams that all sessions of
	// one user carry together: HTTP, TCP and UDP streams alike, counted from
	// TunnelSession.OpenStream until the stream is closed or its session
	// ends. Beyond it OpenStream fails with ErrTooManyUserStreams and the
	// edges refuse the visitor as they do at MaxStreamsPerSession. It does
	// not apply in static-token mode, where sessions have no user. Default
	// 256.
	MaxStreamsPerUser int

	// ControlBurst and ControlRefillPerSecond throttle the control messages
	// of a session after login: a session may send ControlBurst messages at
	// once and regains ControlRefillPerSecond per second. A session that
	// exceeds this is closed. Defaults 20 and 5. A negative value in either
	// field turns the throttle off.
	ControlBurst           int
	ControlRefillPerSecond int

	// MaxSessionsPerUser is the number of sessions one user may have at the
	// same time. It does not apply in static-token mode, where sessions have
	// no user. Default 10.
	MaxSessionsPerUser int

	// MaxSessions is the number of sessions the server carries in total.
	// Default 350.
	MaxSessions int
}

// reservationLookup is the part of reservations.Service the acceptor uses.
type reservationLookup interface {
	Owner(ctx context.Context, subdomain string) (int64, bool, error)
	OwnerTCPPort(ctx context.Context, port int) (int64, bool, error)
	OwnerUDPPort(ctx context.Context, port int) (int64, bool, error)
}

type Acceptor struct {
	opts   Options
	logger *slog.Logger
	lim    limits

	// res is opts.Reservations, or nil without a reservations service.
	res reservationLookup

	// unauth counts the connections that have not authenticated yet.
	unauth *connLimiter
	// userStreams bounds the streams of each user's sessions together; nil
	// when MaxStreamsPerUser is disabled.
	userStreams *userStreams
	// rejected spaces out the log lines about connections over the limit.
	rejected eventLog
	// pingLimits spaces out the log lines about connections closed for
	// too many yamux ping requests.
	pingLimits eventLog
	// extraStreams spaces out the log lines about connections closed
	// because their client opened a second stream.
	extraStreams eventLog
	// openTimeouts spaces out the log lines about sessions closed because
	// their client did not take a new stream in time.
	openTimeouts eventLog

	// The following are fields so that tests can replace them.
	now        func() time.Time // clock of the control message throttle
	random     io.Reader        // source of session IDs
	newSession func(io.ReadWriteCloser, protocol.ServerOptions) (protocol.Session, error)
	// randomSubdomain draws a random tunnel name; nil means the registry's
	// GenerateRandomSubdomain.
	randomSubdomain func() (string, error)
	// verifyToken checks a token against the database: opts.DBVerifier's
	// VerifyWithToken, nil in static-token mode.
	verifyToken func(ctx context.Context, token string) (userID, tokenID int64, ok bool)
}

func New(opts Options) *Acceptor {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Verifier == nil && opts.DBVerifier == nil {
		panic("acceptor.New: exactly one of Verifier or DBVerifier must be set")
	}
	// Reservations only make sense with DBVerifier: the static-token path has
	// no user identity (tunnel.UserID stays 0), so every reservation check
	// would trivially fail and operators would be surprised.
	if opts.Reservations != nil && opts.DBVerifier == nil {
		panic("acceptor.New: Reservations requires DBVerifier")
	}
	// A nil *Manager stored in the interface field would not compare equal
	// to nil and would be called.
	if m, ok := opts.TCPEdge.(*edgetcp.Manager); ok && m == nil {
		opts.TCPEdge = nil
	}
	if m, ok := opts.UDPEdge.(*edgeudp.Manager); ok && m == nil {
		opts.UDPEdge = nil
	}
	lim := resolveLimits(opts)
	a := &Acceptor{
		opts:         opts,
		logger:       opts.Logger,
		lim:          lim,
		unauth:       newConnLimiter(lim.maxUnauthConns, lim.maxUnauthConnsPerIP),
		rejected:     eventLog{interval: time.Second},
		pingLimits:   eventLog{interval: time.Second},
		openTimeouts: eventLog{interval: time.Second},
		extraStreams: eventLog{interval: time.Second},
		now:          time.Now,
		random:       rand.Reader,
		newSession:   protocol.NewServerSessionWithOptions,
	}
	if opts.Reservations != nil {
		a.res = opts.Reservations
	}
	if lim.maxStreamsPerUser > 0 {
		a.userStreams = newUserStreams(lim.maxStreamsPerUser)
	}
	if opts.DBVerifier != nil {
		a.verifyToken = opts.DBVerifier.VerifyWithToken
	}
	return a
}

func (a *Acceptor) Serve(ctx context.Context, ln net.Listener) error {
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			// A failing Accept (for example: out of file descriptors) must
			// not spin: wait, longer each time, until one succeeds again.
			delay = nextAcceptDelay(delay)
			a.logger.Error("accept failed", "err", err, "retry_in", delay)
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil
			}
			continue
		}
		delay = 0

		release, ok := a.unauth.acquire(conn.RemoteAddr())
		if !ok {
			_ = conn.Close()
			if logNow, events := a.rejected.note(time.Now()); logNow {
				a.logger.Warn("unauthenticated connection limit reached, closing new connections",
					"remote", remoteString(conn), "closed", events)
			}
			continue
		}
		go a.handleConn(ctx, conn, release)
	}
}

func remoteString(conn net.Conn) string {
	if addr := conn.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return ""
}

// errRefused ends a connection whose reason has been logged already.
var errRefused = errors.New("connection refused by acceptor")

// handleConn serves one accepted connection. authenticated releases the
// connection's slot among the unauthenticated connections; it is called when
// the login succeeds, and in any case when the connection ends.
func (a *Acceptor) handleConn(ctx context.Context, conn net.Conn, authenticated func()) {
	remote := remoteString(conn)
	// Deferred first, so it runs last, after everything below has released
	// what the connection held. A panic ends this connection, not the server.
	defer func() {
		if r := recover(); r != nil {
			a.logger.Error("panic while serving tunnel connection",
				"remote", remote, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
		}
	}()
	defer authenticated()
	defer conn.Close()

	// The deadline covers everything up to the HelloAck and is not extended
	// on the way: a client that stalls at any point is gone when it expires.
	var handshakeDeadline time.Time // zero: no deadline
	if a.lim.handshakeTimeout > 0 {
		handshakeDeadline = time.Now().Add(a.lim.handshakeTimeout)
		if err := conn.SetDeadline(handshakeDeadline); err != nil {
			a.logger.Warn("cannot set handshake deadline, closing connection", "err", err, "remote", remote)
			return
		}
	}
	if tc, ok := conn.(*tls.Conn); ok {
		if err := tc.HandshakeContext(ctx); err != nil {
			a.logger.Debug("tls handshake failed", "err", err, "remote", remote)
			return
		}
	}

	sess, err := a.newSession(conn, protocol.ServerOptions{
		AcceptBacklog:      a.lim.acceptBacklog,
		StreamCloseTimeout: a.opts.StreamCloseTimeout,
		// A client that asks for more yamux pings than an honest one makes
		// the server park a goroutine per ping; its connection is ended.
		OnPingLimit: func() { a.notePingLimit(remote) },
		// A client opens the control stream and no other; a second one
		// ends its connection before yamux registers it.
		OnStreamLimit: func() { a.noteExtraStream(remote, nil) },
	})
	if err != nil {
		a.logger.Warn("yamux server failed", "err", err, "remote", remote)
		return
	}
	defer sess.Close()

	// Shutdown watchdog: when the server context is cancelled, close the
	// session so any blocked control-stream read unblocks with an error.
	watchdogDone := make(chan struct{})
	defer close(watchdogDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-watchdogDone:
		}
	}()

	ctrl, err := sess.AcceptStream()
	if err != nil {
		a.logger.Debug("connection ended before the control stream", "err", err, "remote", remote)
		return
	}
	// The control stream is not closed on its own: the deferred sess.Close
	// above force-closes it with the session. yamux's Stream.Close on an
	// established stream arms a timer (StreamCloseTimeout, five minutes)
	// that neither its forceClose nor Session.Close stops, and a pending
	// timer keeps the whole closed session in memory: its streams, its
	// buffers and the connection. Every path that ends here with the session
	// still up (a refused hello, a malformed one) would leave that behind.
	//
	// Once the session is closed, what the client left in the control
	// stream's receive buffer is read out and the buffer given back: a
	// closed session that yamux still keeps (a close timer of a stream an
	// edge closed) then holds no control data.
	defer func() {
		_ = sess.Close()
		discardControl(ctrl)
	}()

	// The control stream is the only stream a client opens. Keep accepting
	// so that a further one is noticed instead of sitting in the backlog
	// with a full receive window.
	go a.closeOnExtraStream(sess, remote)

	err = a.serveControl(ctx, conn, sess, ctrl, remote, handshakeDeadline, authenticated)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, errRefused) {
		a.logger.Info("control stream ended", "err", err, "remote", remote)
	}
}

// discardControl reads out the control stream of a closed session and lets
// the stream give back its receive buffer. A yamux stream that its
// session's Close force-closed returns what is buffered and then EOF
// without waiting, and nothing more arrives once the session has stopped
// reading. The number of reads is bounded all the same, by what the
// stream's window lets the client buffer (up to twice the window with
// yamux's buffer growth).
func discardControl(ctrl protocol.Stream) {
	buf := make([]byte, 4<<10)
	for range 2*protocol.StreamWindowBytes/len(buf) + 1 {
		if _, err := ctrl.Read(buf); err != nil {
			break
		}
	}
	edgeguard.Shrink(ctrl)
}

// notePingLimit counts and logs, at most once a second, a connection that is
// ended because its client asked for too many yamux pings.
func (a *Acceptor) notePingLimit(remote string) {
	metrics.RequestTotal.WithLabelValues("tunnel", "ping_limit").Inc()
	if logNow, events := a.pingLimits.note(time.Now()); logNow {
		a.logger.Warn("too many ping requests, closing tunnel connection", "remote", remote, "closed", events)
	}
}

// noteExtraStream counts and logs, at most once a second, a connection that
// is ended because its client opened a second stream: at the frame guard
// below yamux, or at closeOnExtraStream (err, when set, is the error of an
// accept whose ACK timed out). Both are reachable before the login.
func (a *Acceptor) noteExtraStream(remote string, err error) {
	metrics.RequestTotal.WithLabelValues("tunnel", "second_stream").Inc()
	if logNow, events := a.extraStreams.note(time.Now()); logNow {
		args := []any{"remote", remote, "closed", events}
		if err != nil {
			args = append(args, "err", err)
		}
		a.logger.Warn("client opened a second stream, closing tunnel connection", args...)
	}
}

// noteOpenTimeout counts and logs, at most once a second, a session that is
// closed because its client did not take a new stream within the
// connection write timeout. It runs once per closed session, however many
// of its opens failed (TunnelSession.openFailed); the line's "closed" is the
// number of sessions closed since the previous line.
func (a *Acceptor) noteOpenTimeout(sessionID string, userID int64, remote string) {
	metrics.RequestTotal.WithLabelValues("tunnel", "open_timeout").Inc()
	if logNow, events := a.openTimeouts.note(time.Now()); logNow {
		a.logger.Warn("closing tunnel session: the client did not take a new stream in time",
			"session_id", sessionID, "user_id", userID, "remote", remote, "closed", events)
	}
}

// closeOnExtraStream closes the session as soon as the client opens a stream
// besides the control stream, and when the accept fails. It returns when the
// session ends.
//
// An error of AcceptStream is usually the session's end. But yamux also
// fails the accept when the ACK of the client's new stream runs out of the
// connection write timeout (protocol.ErrStreamLeftOpen): the stream stays
// registered and the session lives on, and with this guard gone nothing
// would accept again, so the client could park the streams of the accept
// backlog, each with a full window, for the life of the session. That is a
// second stream as well. Closing a session that has ended is harmless.
//
// The extra stream is not closed on its own: its Close would arm the
// five-minute close timer that keeps the closed session in memory (see
// handleConn), and wait for its FIN to leave while nobody accepts.
// Session.Close force-closes it with the session.
func (a *Acceptor) closeOnExtraStream(sess protocol.Session, remote string) {
	_, err := sess.AcceptStream()
	switch {
	case err == nil:
		a.noteExtraStream(remote, nil)
	case errors.Is(err, protocol.ErrStreamLeftOpen):
		a.noteExtraStream(remote, err)
	}
	_ = sess.Close()
}

// Texts sent to clients. They are fixed: an internal error never travels to
// a client, it is logged here and the client gets one of these.
const (
	errTextInternal          = "internal error"
	errTextBadPayload        = "bad payload"
	errTextInvalidToken      = "invalid token"
	errTextSessionLimit      = "session limit reached"
	errTextServerFull        = "server at capacity"
	errTextInvalidSubdomain  = "invalid subdomain"
	errTextSubdomainReserved = "subdomain reserved"
	errTextSubdomainTaken    = "subdomain taken"
	errTextHTTPAlready       = "session already has a subdomain"
	errTextTCPDisabled       = "tcp tunneling disabled"
	errTextTCPAlready        = "session already has a tcp port"
	errTextUDPDisabled       = "udp tunneling disabled"
	errTextUDPAlready        = "session already has a udp port"
	errTextPortOutOfRange    = "port out of range"
	errTextPortUnavailable   = "port unavailable"
	errTextPortReserved      = "port reserved"
	errTextPortNotReserved   = "port not reserved"
	errTextNoPorts           = "no ports available"
)

const (
	// maxLoggedTypeLen is how much of a client-chosen message type is logged.
	maxLoggedTypeLen = 32
	// maxUnknownMessages is the number of messages with an unknown or
	// misdirected type at which the session is closed.
	maxUnknownMessages = 3
	// maxPortDraws bounds how often a port is drawn for one request with
	// port 0 when the drawn ports turn out to be reserved for other users.
	maxPortDraws = 8
	// handshakeAnswerReserve is the part of the handshake deadline that the
	// second token check leaves for the answer, at most a quarter of the
	// deadline: one small frame that has to reach the connection.
	handshakeAnswerReserve = 500 * time.Millisecond
	// maxPort is the highest port number.
	maxPort = 65535
)

// authenticate checks the client's token. It returns the user the token
// belongs to and the ID of the token; both are 0 in static-token mode. It is
// the only place that calls a verifier.
//
// The token ID travels with the session into the registry, so that
// Registry.KillByToken can close the sessions of a revoked token and the
// server's revalidation can find sessions whose token stopped being valid.
func (a *Acceptor) authenticate(ctx context.Context, token string) (userID, tokenID int64, ok bool) {
	if a.verifyToken == nil {
		return 0, 0, a.opts.Verifier.Verify(token)
	}
	if a.lim.verifyTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.lim.verifyTimeout)
		defer cancel()
	}
	uid, tid, ok := a.verifyToken(ctx, token)
	if !ok || uid <= 0 || tid <= 0 {
		// A database session without a user would pass every ownership
		// check that compares against "no user", and one without a token
		// could not be selected by KillByToken or the revalidation.
		return 0, 0, false
	}
	return uid, tid, true
}

// refuseHello answers the hello with an error. The caller then ends the
// connection.
func (a *Acceptor) refuseHello(ctrl protocol.Stream, text string) {
	_ = writeEnvelope(ctrl, protocol.TypeHelloAck, &protocol.HelloAck{Error: text})
	// Give yamux a moment to flush the HelloAck to the wire before the
	// deferred session.Close() tears down the yamux session. Without this
	// the client can observe "session shutdown" on its next Read instead of
	// the clean error response we just wrote.
	time.Sleep(50 * time.Millisecond)
}

func (a *Acceptor) serveControl(ctx context.Context, conn net.Conn, sess protocol.Session, ctrl protocol.Stream, remote string, handshakeDeadline time.Time, authenticated func()) error {
	env, err := readEnvelope(ctrl, a.lim.preAuthFrameSize)
	if err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	if env.Type != protocol.TypeHello {
		return fmt.Errorf("expected hello, got %q", clip(string(env.Type), maxLoggedTypeLen))
	}
	var hello protocol.Hello
	if err := json.Unmarshal(env.Payload, &hello); err != nil {
		return fmt.Errorf("unmarshal hello: %w", err)
	}

	userID, tokenID, ok := a.authenticate(ctx, hello.Token)
	if !ok {
		metrics.AuthAttemptsTotal.WithLabelValues("fail").Inc()
		a.logger.Warn("authentication failed", "remote", remote)
		a.refuseHello(ctrl, errTextInvalidToken)
		return errRefused
	}

	sessionID, err := newSessionID(a.random)
	if err != nil {
		a.logger.Error("cannot create session id", "err", err, "remote", remote)
		a.refuseHello(ctrl, errTextInternal)
		return errRefused
	}
	tunnel := newTunnelSession(sessionID, userID, tokenID, sess, a.lim.maxStreams)
	tunnel.onOpenTimeout = func() { a.noteOpenTimeout(tunnel.id, userID, remote) }
	if userID > 0 && a.userStreams != nil {
		// Static-token sessions (user 0) have no user to share a limit with.
		tunnel.user = a.userStreams
	}

	// From here on the registry knows the session: it is listed and can be
	// killed, whether or not it ever registers a tunnel.
	err = a.opts.Registry.AddSession(tunnel, a.lim.sessionLimits())
	if err != nil {
		text := errTextInternal
		switch {
		case errors.Is(err, registry.ErrUserSessionLimit):
			text = errTextSessionLimit
		case errors.Is(err, registry.ErrSessionLimit):
			text = errTextServerFull
		}
		a.logger.Warn("session refused", "reason", err, "user_id", userID, "remote", remote)
		a.refuseHello(ctrl, text)
		return errRefused
	}
	defer a.teardown(tunnel)

	// A token revoked or an account disabled between the check above and
	// AddSession found no session to close (KillByToken, KillByUser), so the
	// session would live until the next revalidation. Now that the registry
	// lists it, check once more; a refusal or a failed check ends it. Static
	// tokens are fixed for the life of the process: nothing to check again.
	//
	// The check ends in time for the answer to reach the client before the
	// handshake deadline: with a slow database two checks could take longer
	// than the deadline, the answer would meet a connection past it and the
	// client would see the connection dropped, while the session stayed in
	// the registry until the check returned.
	if a.verifyToken != nil {
		checkCtx := ctx
		if !handshakeDeadline.IsZero() {
			reserve := min(handshakeAnswerReserve, a.lim.handshakeTimeout/4)
			var cancel context.CancelFunc
			checkCtx, cancel = context.WithDeadline(ctx, handshakeDeadline.Add(-reserve))
			defer cancel()
		}
		if uid, tid, ok := a.authenticate(checkCtx, hello.Token); !ok || uid != userID || tid != tokenID {
			metrics.AuthAttemptsTotal.WithLabelValues("fail").Inc()
			a.logger.Warn("authentication failed at the second check", "user_id", userID, "remote", remote)
			a.refuseHello(ctrl, errTextInvalidToken)
			return errRefused
		}
	}
	metrics.AuthAttemptsTotal.WithLabelValues("success").Inc()

	if err := writeEnvelope(ctrl, protocol.TypeHelloAck, &protocol.HelloAck{SessionID: sessionID, ServerVersion: a.opts.ServerVersion}); err != nil {
		return fmt.Errorf("write hello_ack: %w", err)
	}
	// The handshake is complete: lift the deadline and stop counting the
	// connection as unauthenticated.
	if a.lim.handshakeTimeout > 0 {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			return fmt.Errorf("clear handshake deadline: %w", err)
		}
	}
	authenticated()

	throttle := newTokenBucket(a.lim.controlBurst, a.lim.controlRefill, a.now())
	unknown := 0
	for {
		env, err := readEnvelope(ctrl, a.lim.controlFrameSize)
		if err != nil {
			return err
		}
		// Frames that arrive while a message is being handled wait in the
		// control stream's receive buffer, which yamux then keeps at that
		// size for the life of the session. Once it is empty again the
		// stream gives the memory back.
		edgeguard.Shrink(ctrl)
		if !throttle.allow(a.now()) {
			a.logger.Warn("control message rate exceeded, closing session",
				"session_id", tunnel.id, "user_id", userID, "remote", remote)
			return errRefused
		}
		switch env.Type {
		case protocol.TypeRegisterHTTP:
			a.handleRegisterHTTP(ctx, ctrl, env.Payload, tunnel)
		case protocol.TypeRegisterTCP:
			a.handleRegisterTCP(ctx, ctrl, env.Payload, tunnel)
		case protocol.TypeRegisterUDP:
			a.handleRegisterUDP(ctx, ctrl, env.Payload, tunnel)
		case protocol.TypePing:
			_ = writeEnvelope(ctrl, protocol.TypePong, nil)
		default:
			// The type is text chosen by the client: log a bounded part.
			unknown++
			a.logger.Warn("unknown message type",
				"type", clip(string(env.Type), maxLoggedTypeLen), "count", unknown,
				"session_id", tunnel.id, "remote", remote)
			if unknown >= maxUnknownMessages {
				a.logger.Warn("too many unknown messages, closing session",
					"session_id", tunnel.id, "user_id", userID, "remote", remote)
				return errRefused
			}
		}
	}
}

// teardown ends a session. The registry is cleaned first and the ports are
// given back afterwards: as long as the registry lists a port for this
// session nobody else must be handed that port, and once the port is free
// again there must be no stale entry that a new holder would collide with.
func (a *Acceptor) teardown(tunnel *TunnelSession) {
	_ = tunnel.Close()
	a.opts.Registry.Unregister(tunnel)
	if port := tunnel.tcp.take(); port != 0 && a.opts.TCPEdge != nil {
		a.opts.TCPEdge.Close(port)
	}
	if port := tunnel.udp.take(); port != 0 && a.opts.UDPEdge != nil {
		a.opts.UDPEdge.Close(port)
	}
}

// registryErrText maps an error of a Registry.Register call to the text for
// the client.
func registryErrText(err error) string {
	switch {
	case errors.Is(err, registry.ErrSubdomainTaken):
		return errTextSubdomainTaken
	case errors.Is(err, registry.ErrSessionAlreadyRegistered):
		return errTextHTTPAlready
	case errors.Is(err, registry.ErrSessionAlreadyRegisteredTCP):
		return errTextTCPAlready
	case errors.Is(err, registry.ErrSessionAlreadyRegisteredUDP):
		return errTextUDPAlready
	case errors.Is(err, registry.ErrPortTaken), errors.Is(err, registry.ErrUDPPortTaken):
		return errTextPortUnavailable
	case errors.Is(err, reservations.ErrSystemReserved):
		return errTextSubdomainReserved
	case errors.Is(err, reservations.ErrInvalidSubdomain):
		return errTextInvalidSubdomain
	}
	return errTextInternal
}

func (a *Acceptor) handleRegisterHTTP(ctx context.Context, ctrl protocol.Stream, payload json.RawMessage, tunnel *TunnelSession) {
	var req protocol.RegisterHTTP
	if err := json.Unmarshal(payload, &req); err != nil {
		_ = writeEnvelope(ctrl, protocol.TypeRegisterHTTPAck, &protocol.RegisterHTTPAck{Error: errTextBadPayload})
		return
	}
	subdomain, errText := a.registerHTTP(ctx, req.Subdomain, tunnel)
	if errText != "" {
		_ = writeEnvelope(ctrl, protocol.TypeRegisterHTTPAck, &protocol.RegisterHTTPAck{Error: errText})
		return
	}
	publicURL := fmt.Sprintf("https://%s.%s", subdomain, a.opts.Domain)
	_ = writeEnvelope(ctrl, protocol.TypeRegisterHTTPAck, &protocol.RegisterHTTPAck{
		PublicURL: publicURL,
		Subdomain: subdomain,
	})
	a.logger.Info("http tunnel registered", "subdomain", subdomain, "session_id", tunnel.id, "user_id", tunnel.UserID)
}

// maxSubdomainDraws bounds how often a random name is drawn for one request
// when the drawn names turn out to be reserved for other users or taken.
const maxSubdomainDraws = 8

// registerHTTP registers an HTTP tunnel under the requested name, or under a
// random name when requested is empty. It returns the registered name, or
// the error text for the client.
func (a *Acceptor) registerHTTP(ctx context.Context, requested string, tunnel *TunnelSession) (subdomain, errText string) {
	if requested == "" {
		return a.registerRandomHTTP(ctx, tunnel)
	}
	// Validate before anything else sees the name: an invalid or
	// system-reserved name reaches neither the database nor the log.
	name, err := reservations.NormalizeSubdomain(requested)
	switch {
	case errors.Is(err, reservations.ErrSystemReserved):
		return "", errTextSubdomainReserved
	case err != nil:
		return "", errTextInvalidSubdomain
	}
	if text := a.subdomainRefusal(ctx, name, tunnel.UserID); text != "" {
		return "", text
	}
	if err := a.opts.Registry.RegisterHTTP(name, tunnel); err != nil {
		return "", a.httpRegistryErrText(err, tunnel)
	}
	// Nothing locks the reservation table against the registry. Whoever
	// reserves a name evicts the foreign session that serves it; a
	// reservation made between the check above and the registration found
	// no session to evict, so look again now that there is one.
	if text := a.subdomainRefusal(ctx, name, tunnel.UserID); text != "" {
		a.opts.Registry.UnregisterHTTP(name, tunnel)
		return "", text
	}
	return name, ""
}

// registerRandomHTTP registers an HTTP tunnel under a randomly drawn name. A
// drawn name goes through the same reservation checks as a requested one,
// before and after the registration; a name that is reserved for another
// user, or that another session registered meanwhile, is given up and
// another one drawn, at most maxSubdomainDraws times. A lookup that fails
// refuses at once.
func (a *Acceptor) registerRandomHTTP(ctx context.Context, tunnel *TunnelSession) (subdomain, errText string) {
	draw := a.randomSubdomain
	if draw == nil {
		draw = a.opts.Registry.GenerateRandomSubdomain
	}
	for i := 0; i < maxSubdomainDraws; i++ {
		name, err := draw()
		if err != nil {
			a.logger.Error("subdomain generation failed", "err", err, "session_id", tunnel.id)
			return "", errTextInternal
		}
		switch text := a.subdomainRefusal(ctx, name, tunnel.UserID); text {
		case "":
		case errTextSubdomainReserved:
			continue // reserved for somebody else: draw again
		default:
			return "", text
		}
		if err := a.opts.Registry.RegisterHTTP(name, tunnel); err != nil {
			if errors.Is(err, registry.ErrSubdomainTaken) {
				continue // registered by another session since the draw
			}
			return "", a.httpRegistryErrText(err, tunnel)
		}
		// Look again now that the session holds the name (see registerHTTP).
		text := a.subdomainRefusal(ctx, name, tunnel.UserID)
		if text == "" {
			return name, ""
		}
		a.opts.Registry.UnregisterHTTP(name, tunnel)
		if text != errTextSubdomainReserved {
			return "", text
		}
	}
	a.logger.Warn("no unreserved subdomain drawn", "draws", maxSubdomainDraws, "session_id", tunnel.id)
	return "", errTextInternal
}

// httpRegistryErrText returns the client's text for an error of
// Registry.RegisterHTTP and logs an error that has no text of its own.
func (a *Acceptor) httpRegistryErrText(err error, tunnel *TunnelSession) string {
	text := registryErrText(err)
	if text == errTextInternal {
		a.logger.Error("http registration failed", "err", err, "session_id", tunnel.id)
	}
	return text
}

// lookupContext bounds one reservation lookup with the verify timeout, like
// the token check. A lookup that runs out of it fails, and a failed lookup
// refuses: during a database stall a session's control loop waits at most
// that long, and a session killed meanwhile gives its port back after it.
func (a *Acceptor) lookupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if a.lim.verifyTimeout > 0 {
		return context.WithTimeout(ctx, a.lim.verifyTimeout)
	}
	return ctx, func() {}
}

// subdomainRefusal returns the error text if userID may not serve the
// subdomain because it is reserved for somebody else, and "" if it may. A
// lookup that fails refuses.
func (a *Acceptor) subdomainRefusal(ctx context.Context, subdomain string, userID int64) string {
	if a.res == nil {
		return ""
	}
	ctx, cancel := a.lookupContext(ctx)
	defer cancel()
	owner, reserved, err := a.res.Owner(ctx, subdomain)
	if err != nil {
		a.logger.Error("reservation lookup failed", "err", err, "kind", "http")
		return errTextInternal
	}
	if reserved && owner != userID {
		return errTextSubdomainReserved
	}
	return ""
}

// portKind bundles what differs between TCP and UDP port tunnels.
type portKind struct {
	name        string // "tcp" or "udp"
	alreadyText string
	slot        *portSlot
	open        func(ctx context.Context, preferred int) (int, error)
	close       func(port int)
	register    func(port int) error
	unregister  func(port int)
	owner       func(ctx context.Context, port int) (int64, bool, error) // nil without reservations
	openErrText func(error) string
}

func (a *Acceptor) tcpPorts(tunnel *TunnelSession) portKind {
	k := portKind{
		name:        "tcp",
		alreadyText: errTextTCPAlready,
		slot:        &tunnel.tcp,
		open: func(ctx context.Context, preferred int) (int, error) {
			return a.opts.TCPEdge.Open(ctx, preferred, tunnel)
		},
		close:      func(port int) { a.opts.TCPEdge.Close(port) },
		register:   func(port int) error { return a.opts.Registry.RegisterTCP(port, tunnel) },
		unregister: func(port int) { a.opts.Registry.UnregisterTCP(port, tunnel) },
		openErrText: func(err error) string {
			switch {
			case errors.Is(err, edgetcp.ErrPortOutOfRange):
				return errTextPortOutOfRange
			case errors.Is(err, edgetcp.ErrPoolExhausted):
				return errTextNoPorts
			}
			return errTextPortUnavailable // taken, or the listener could not be opened
		},
	}
	if a.res != nil {
		k.owner = a.res.OwnerTCPPort
	}
	return k
}

func (a *Acceptor) udpPorts(tunnel *TunnelSession) portKind {
	k := portKind{
		name:        "udp",
		alreadyText: errTextUDPAlready,
		slot:        &tunnel.udp,
		open: func(ctx context.Context, preferred int) (int, error) {
			return a.opts.UDPEdge.Open(ctx, preferred, tunnel)
		},
		close:      func(port int) { a.opts.UDPEdge.Close(port) },
		register:   func(port int) error { return a.opts.Registry.RegisterUDP(port, tunnel) },
		unregister: func(port int) { a.opts.Registry.UnregisterUDP(port, tunnel) },
		openErrText: func(err error) string {
			switch {
			case errors.Is(err, edgeudp.ErrPortOutOfRange):
				return errTextPortOutOfRange
			case errors.Is(err, edgeudp.ErrPoolExhausted):
				return errTextNoPorts
			}
			return errTextPortUnavailable
		},
	}
	if a.res != nil {
		k.owner = a.res.OwnerUDPPort
	}
	return k
}

// portRefusal returns the error text if userID may not use the port, and ""
// if it may. A port reserved for another user is always refused. With
// mustOwn the port must in addition be reserved for userID. A lookup that
// fails refuses.
func (a *Acceptor) portRefusal(ctx context.Context, k portKind, port int, userID int64, mustOwn bool) string {
	if k.owner == nil {
		if mustOwn {
			// No reservations service: nothing is reserved for anybody.
			return errTextPortNotReserved
		}
		return ""
	}
	ctx, cancel := a.lookupContext(ctx)
	defer cancel()
	owner, reserved, err := k.owner(ctx, port)
	if err != nil {
		a.logger.Error("reservation lookup failed", "err", err, "kind", k.name)
		return errTextInternal
	}
	switch {
	case reserved && owner != userID:
		return errTextPortReserved
	case !reserved && mustOwn:
		return errTextPortNotReserved
	}
	return ""
}

// registerPort opens and registers a port tunnel. requested is the port the
// client asked for, 0 for "any". It returns the port, or the error text for
// the client.
func (a *Acceptor) registerPort(ctx context.Context, k portKind, requested int, tunnel *TunnelSession) (port int, errText string) {
	// The session's own record decides whether it already holds a port, and
	// it decides before a listener is opened. The registry cannot: an admin
	// kill removes the registry entries before the session is gone, and a
	// second listener would then replace the record of the first, which
	// would stay open with nobody left to close it.
	if k.slot.get() != 0 {
		return 0, k.alreadyText
	}
	// Reservations are stored as 32-bit ports: check the range before any
	// lookup can see the number.
	if requested < 0 || requested > maxPort {
		return 0, errTextPortOutOfRange
	}

	// In database mode a client gets a specific port only if that port is
	// reserved for its user. Otherwise anybody could take a port the moment
	// its holder disconnects, or sit on a port somebody is about to reserve.
	specific := requested != 0
	mustOwn := specific && a.opts.DBVerifier != nil
	if specific {
		if text := a.portRefusal(ctx, k, requested, tunnel.UserID, mustOwn); text != "" {
			return 0, text
		}
	}

	draws := 1
	if !specific {
		draws = maxPortDraws
	}
	for i := 0; i < draws; i++ {
		port, err := k.open(ctx, requested)
		if err != nil {
			a.logger.Warn("opening tunnel port failed", "kind", k.name, "requested", requested, "err", err, "session_id", tunnel.id)
			return 0, k.openErrText(err)
		}
		if err := k.register(port); err != nil {
			k.close(port)
			a.logger.Warn("registering tunnel port failed", "kind", k.name, "port", port, "err", err, "session_id", tunnel.id)
			return 0, registryErrText(err)
		}

		// The check after the registration covers both cases: a port drawn
		// for "any" may be one that is reserved for somebody else, and a
		// reservation may have changed since the check above (see
		// registerHTTP for why looking again after registering closes that
		// gap).
		text := a.portRefusal(ctx, k, port, tunnel.UserID, mustOwn)
		if text == "" {
			k.slot.set(port)
			return port, ""
		}
		k.unregister(port)
		k.close(port)
		if specific || text != errTextPortReserved {
			return 0, text
		}
		// A drawn port that belongs to somebody else: draw again.
	}
	a.logger.Warn("no unreserved port drawn", "kind", k.name, "draws", draws, "session_id", tunnel.id)
	return 0, errTextNoPorts
}

func (a *Acceptor) handleRegisterTCP(ctx context.Context, ctrl protocol.Stream, payload json.RawMessage, tunnel *TunnelSession) {
	var req protocol.RegisterTCP
	if err := json.Unmarshal(payload, &req); err != nil {
		_ = writeEnvelope(ctrl, protocol.TypeRegisterTCPAck, &protocol.RegisterTCPAck{Error: errTextBadPayload})
		return
	}
	if a.opts.TCPEdge == nil {
		_ = writeEnvelope(ctrl, protocol.TypeRegisterTCPAck, &protocol.RegisterTCPAck{Error: errTextTCPDisabled})
		return
	}
	port, errText := a.registerPort(ctx, a.tcpPorts(tunnel), req.Port, tunnel)
	if errText != "" {
		_ = writeEnvelope(ctrl, protocol.TypeRegisterTCPAck, &protocol.RegisterTCPAck{Error: errText})
		return
	}
	publicAddr := fmt.Sprintf("%s:%d", a.opts.Domain, port)
	_ = writeEnvelope(ctrl, protocol.TypeRegisterTCPAck, &protocol.RegisterTCPAck{
		PublicAddr: publicAddr,
		Port:       port,
	})
	a.logger.Info("tcp tunnel registered", "port", port, "session_id", tunnel.id, "user_id", tunnel.UserID)
}

func (a *Acceptor) handleRegisterUDP(ctx context.Context, ctrl protocol.Stream, payload json.RawMessage, tunnel *TunnelSession) {
	var req protocol.RegisterUDP
	if err := json.Unmarshal(payload, &req); err != nil {
		_ = writeEnvelope(ctrl, protocol.TypeRegisterUDPAck, &protocol.RegisterUDPAck{Error: errTextBadPayload})
		return
	}
	if a.opts.UDPEdge == nil {
		_ = writeEnvelope(ctrl, protocol.TypeRegisterUDPAck, &protocol.RegisterUDPAck{Error: errTextUDPDisabled})
		return
	}
	port, errText := a.registerPort(ctx, a.udpPorts(tunnel), req.Port, tunnel)
	if errText != "" {
		_ = writeEnvelope(ctrl, protocol.TypeRegisterUDPAck, &protocol.RegisterUDPAck{Error: errText})
		return
	}
	publicAddr := fmt.Sprintf("%s:%d", a.opts.Domain, port)
	_ = writeEnvelope(ctrl, protocol.TypeRegisterUDPAck, &protocol.RegisterUDPAck{
		PublicAddr: publicAddr,
		Port:       port,
	})
	a.logger.Info("udp tunnel registered", "port", port, "session_id", tunnel.id, "user_id", tunnel.UserID)
}

// readEnvelope reads one control message of at most maxSize bytes.
func readEnvelope(r io.Reader, maxSize uint32) (*protocol.Envelope, error) {
	raw, err := protocol.ReadFrame(r, maxSize)
	if err != nil {
		return nil, err
	}
	var env protocol.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	return &env, nil
}

func writeEnvelope(w io.Writer, t protocol.MessageType, payload interface{}) error {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		raw = b
	}
	b, err := json.Marshal(protocol.Envelope{Type: t, Payload: raw})
	if err != nil {
		return err
	}
	return protocol.WriteFrame(w, b)
}
