package protocol

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/yamux"
)

// Session is the minimal surface both client and server need from yamux.
type Session interface {
	OpenStream() (Stream, error)
	AcceptStream() (Stream, error)
	Close() error
}

// Stream is an individual bidirectional stream within a session.
type Stream interface {
	io.ReadWriteCloser
}

// StreamCounter is implemented by sessions that can report how many streams
// are currently live. A stream stays live until both ends have closed it, so
// the count includes streams that this side has already closed but the peer
// has not.
type StreamCounter interface {
	NumStreams() int
}

// ErrStreamLeftOpen is returned (wrapping yamux's error) by a session's
// OpenStream when the peer did not take the new stream within the
// connection write timeout. yamux v0.1.2 registers a new stream in the
// session before it sends the SYN and, when that send times out, returns the
// error without removing the stream (session.go OpenStream): the peer can
// still accept the late SYN and write on a stream that nobody on this side
// has a handle to, reads or closes. The caller has to end the session. The
// other errors of OpenStream leave nothing behind: the session is shut down
// (ErrSessionShutdown, before or while sending; a dead session releases its
// streams), the peer sent go-away (ErrRemoteGoAway), the stream ids are used
// up (ErrStreamsExhausted) — all before the stream is registered.
//
// AcceptStream returns it as well when the ACK of the peer's new stream
// runs out of the connection write timeout: yamux registered the stream
// when its SYN arrived and returns the error without removing it (session.go
// AcceptStream), so nothing on this side has a handle to it. Its other error
// is the session's end.
var ErrStreamLeftOpen = errors.New("protocol: the peer did not take a new stream in time")

type yamuxSession struct {
	s *yamux.Session
}

func (y *yamuxSession) OpenStream() (Stream, error) {
	st, err := y.s.OpenStream()
	if err != nil {
		if errors.Is(err, yamux.ErrConnectionWriteTimeout) {
			return nil, fmt.Errorf("%w: %w", ErrStreamLeftOpen, err)
		}
		return nil, err
	}
	return st, nil
}

func (y *yamuxSession) AcceptStream() (Stream, error) {
	st, err := y.s.AcceptStream()
	if err != nil {
		if errors.Is(err, yamux.ErrConnectionWriteTimeout) {
			return nil, fmt.Errorf("%w: %w", ErrStreamLeftOpen, err)
		}
		return nil, err
	}
	return st, nil
}

func (y *yamuxSession) Close() error    { return y.s.Close() }
func (y *yamuxSession) NumStreams() int { return y.s.NumStreams() }

// StreamWindowBytes is the receive window of every stream: the bytes the
// peer may send on a stream that this side has not read yet. It is yamux's
// default, and yamux v0.1.2 refuses a smaller MaxStreamWindowSize, so it
// cannot be lowered. yamux keeps the unread bytes in a buffer that starts at
// the size of the first frame and doubles when a frame does not fit, so one
// stream whose reader stalls can hold up to about twice the window.
const StreamWindowBytes = 256 << 10

// yamux's StreamCloseTimeout (5 minutes) stays as it is on both sides. When
// this side closes a stream, yamux starts that timer and then resets the
// stream, whatever is still moving on it. The edges close their side of a
// stream when the visitor has finished sending and go on reading the
// backend's answer (a half-close, edgetcp and edgehttp), so a shorter timeout
// would cut those answers: the answer of a TCP or HTTP tunnel ends at the
// latest five minutes after the visitor half-closed. The flip side: a stream
// the server has closed can live that long when the client keeps it open.
// Once an edge is completely done with such a stream, it reads and discards
// what the client still sends (at a pace for HTTP and TCP) and keeps
// counting the stream against its total until the stream is gone
// (edgeguard.RetirePaced, edgeguard.Retire).

func defaultConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = true
	c.KeepAliveInterval = DefaultKeepAliveInterval
	c.ConnectionWriteTimeout = ConnectionWriteTimeout
	c.LogOutput = io.Discard
	return c
}

// DefaultServerAcceptBacklog is the accept backlog of a server session when
// ServerOptions.AcceptBacklog is zero.
const DefaultServerAcceptBacklog = 32

// ServerOptions tunes a server session. A zero value selects the default; a
// negative value disables the limit.
type ServerOptions struct {
	// AcceptBacklog is the number of streams opened by the client that may wait
	// for AcceptStream; the server resets further ones. yamux uses the same
	// number for the streams the server has opened and the client has not
	// accepted yet: OpenStream waits while that many are outstanding.
	//
	// Zero selects DefaultServerAcceptBacklog. A negative value disables the
	// reduced limit and leaves yamux's own default (256) in place.
	AcceptBacklog int

	// PingBurst and PingRefill are the allowance of ping requests from the
	// client (see the frame guard): PingBurst at once, one more every
	// PingRefill. Zero selects DefaultPingBurst and DefaultPingRefill; a
	// negative PingBurst switches the ping rule off.
	PingBurst  int
	PingRefill time.Duration
	// PeerStreams is the number of streams the client may open on the
	// connection (see the frame guard). Zero selects DefaultPeerStreams;
	// a negative value switches the rule off (only for tests of the
	// acceptor's own guard).
	PeerStreams int

	// OnStreamLimit, when set, is called once when a client opens a
	// stream beyond PeerStreams; its connection is then ended.
	OnStreamLimit func()

	// OnPingLimit, when set, is called once when a client exceeds the
	// allowance, just before its connection is ended.
	OnPingLimit func()

	// ConnectionWriteTimeout, when positive, replaces ConnectionWriteTimeout
	// for this session. For tests.
	ConnectionWriteTimeout time.Duration

	// StreamCloseTimeout, when positive, replaces yamux's StreamCloseTimeout
	// (five minutes): how long a stream this side closed waits for the
	// peer's FIN before yamux removes it. For the memory measurement.
	StreamCloseTimeout time.Duration
}

// NewServerSession wraps an accepted net.Conn as a yamux server session with
// the default ServerOptions.
func NewServerSession(conn io.ReadWriteCloser) (Session, error) {
	return NewServerSessionWithOptions(conn, ServerOptions{})
}

// NewServerSessionWithOptions wraps an accepted net.Conn as a yamux server
// session.
func NewServerSessionWithOptions(conn io.ReadWriteCloser, opts ServerOptions) (Session, error) {
	c := defaultConfig()
	if opts.ConnectionWriteTimeout > 0 {
		c.ConnectionWriteTimeout = opts.ConnectionWriteTimeout
	}
	if opts.StreamCloseTimeout > 0 {
		c.StreamCloseTimeout = opts.StreamCloseTimeout
	}
	switch {
	case opts.AcceptBacklog == 0:
		c.AcceptBacklog = DefaultServerAcceptBacklog
	case opts.AcceptBacklog > 0:
		c.AcceptBacklog = opts.AcceptBacklog
	}
	if opts.PingBurst >= 0 || opts.PeerStreams >= 0 {
		burst, refill := opts.PingBurst, opts.PingRefill
		if burst == 0 {
			burst = DefaultPingBurst
		}
		if refill <= 0 {
			refill = DefaultPingRefill
		}
		g := newFrameGuard(conn, max(burst, 0), refill, time.Now, opts.OnPingLimit)
		g.pingsOff = opts.PingBurst < 0
		switch {
		case opts.PeerStreams == 0:
			g.maxOpens = DefaultPeerStreams
		case opts.PeerStreams > 0:
			g.maxOpens = opts.PeerStreams
		}
		g.onStreams = opts.OnStreamLimit
		conn = guardedConn{ReadWriteCloser: conn, guard: g}
	}
	s, err := yamux.Server(conn, c)
	if err != nil {
		return nil, err
	}
	return &yamuxSession{s: s}, nil
}

// NewClientSession wraps a dialed net.Conn as a yamux client session.
func NewClientSession(conn io.ReadWriteCloser) (Session, error) {
	s, err := yamux.Client(conn, defaultConfig())
	if err != nil {
		return nil, err
	}
	return &yamuxSession{s: s}, nil
}
