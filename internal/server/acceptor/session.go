package acceptor

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
)

// ErrTooManyStreams is returned by TunnelSession.OpenStream when the session
// already carries the maximum number of data streams.
var ErrTooManyStreams = errors.New("too many streams on tunnel session")

// portSlot is the session's own record of the port it holds for one protocol.
// 0 means "none".
type portSlot struct {
	mu   sync.Mutex
	port int
}

func (p *portSlot) get() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.port
}

func (p *portSlot) set(port int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.port = port
}

// take returns the port and clears the slot.
func (p *portSlot) take() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	port := p.port
	p.port = 0
	return port
}

type TunnelSession struct {
	id          string
	UserID      int64 // 0 for static-token sessions (no user concept)
	TokenID     int64 // ID of the API token that authenticated the session; 0 in static-token mode
	ConnectedAt time.Time
	ymux        protocol.Session
	closed      chan struct{}
	closeMu     sync.Mutex

	// streams is the semaphore of OpenStream: one slot per data stream that
	// has been opened and not closed yet. nil means "no limit".
	streams chan struct{}

	// user bounds the streams of all sessions of this session's user. nil
	// means "no limit": the limit is disabled, or the session has no user.
	// It is set before the session is shared and not changed afterwards.
	user *userStreams

	tcp portSlot // the TCP port this session holds
	udp portSlot // the UDP port this session holds

	// onOpenTimeout, when set, is called once when the session has been
	// closed because an open failed for a client that did not take the new
	// stream in time: by the open whose Close closed the session, so that
	// many opens failing at once count as one closed session. It is set
	// before the session is shared.
	onOpenTimeout func()
}

// newTunnelSession builds the session object for an authenticated
// connection. maxStreams of zero or less means "no stream limit".
func newTunnelSession(id string, userID, tokenID int64, ymux protocol.Session, maxStreams int) *TunnelSession {
	t := &TunnelSession{
		id:          id,
		UserID:      userID,
		TokenID:     tokenID,
		ConnectedAt: time.Now(),
		ymux:        ymux,
		closed:      make(chan struct{}),
	}
	if maxStreams > 0 {
		t.streams = make(chan struct{}, maxStreams)
	}
	return t
}

func (t *TunnelSession) ID() string { return t.id }

// UserIDValue returns the owning user_id, or 0 for static-token sessions.
func (t *TunnelSession) UserIDValue() int64 { return t.UserID }

// TokenIDValue returns the ID of the API token that authenticated the
// session, or 0 in static-token mode.
func (t *TunnelSession) TokenIDValue() int64 { return t.TokenID }

// ConnectedAtValue returns when the session's control handshake completed.
func (t *TunnelSession) ConnectedAtValue() time.Time { return t.ConnectedAt }

// OpenStream opens a data stream to the client. A session carries a limited
// number of data streams, and so do all sessions of one user together; when
// either limit is reached OpenStream returns ErrTooManyStreams (for the
// user's limit ErrTooManyUserStreams, which wraps it) at once instead of
// waiting.
//
// The slots of a stream are released when the returned stream is closed. A
// stream that the client has not closed on its side still occupies memory on
// the server, so such streams keep counting until the client is done with
// them: a client cannot make the server hold an unbounded number of
// half-closed streams.
func (t *TunnelSession) OpenStream() (protocol.Stream, error) {
	if t.streams == nil && t.user == nil {
		s, err := t.ymux.OpenStream()
		if err != nil {
			t.openFailed(err)
			return nil, err
		}
		return s, nil
	}
	var releases []func()
	releaseAll := func() {
		for _, release := range releases {
			release()
		}
	}

	if t.streams != nil {
		select {
		case t.streams <- struct{}{}:
		default:
			return nil, ErrTooManyStreams
		}
		releases = append(releases, func() { <-t.streams })
		// The control stream is one of the session's live streams; the rest
		// are data streams, including those only the client has left open.
		if t.liveDataStreams() >= cap(t.streams) {
			releaseAll()
			return nil, ErrTooManyStreams
		}
	}
	if t.user != nil {
		release, err := t.user.acquire(t)
		if err != nil {
			releaseAll()
			return nil, err
		}
		releases = append(releases, release)
	}

	s, err := t.ymux.OpenStream()
	if err != nil {
		releaseAll()
		t.openFailed(err)
		return nil, err
	}
	return limitStream(s, releaseAll), nil
}

// openFailed ends the session when a failed open left its stream registered
// in yamux (protocol.ErrStreamLeftOpen): the client did not take the new
// stream within the connection write timeout. The session has no handle to
// that stream, and the client could later accept it and fill a window that
// nothing reads or closes, outside every limit. A client that cannot take a
// SYN in time is treated like one that failed a keep-alive: the session is
// closed, which takes its registrations, ports and places with it. The
// shipped client does not reconnect: the tunnel command ends with its
// session (cmd/tunnel returns on the first error of its accept loop) and
// has to be started again. The other errors of an open leave nothing behind
// and keep their handling.
func (t *TunnelSession) openFailed(err error) {
	if !errors.Is(err, protocol.ErrStreamLeftOpen) {
		return
	}
	if closed, _ := t.shutDown(); closed && t.onOpenTimeout != nil {
		t.onOpenTimeout()
	}
}

// liveDataStreams returns the number of data streams the yamux session
// still keeps, including those the server has closed and the client has
// not. It is 0 for a session that cannot count its streams.
func (t *TunnelSession) liveDataStreams() int {
	if c, ok := t.ymux.(protocol.StreamCounter); ok {
		return max(c.NumStreams()-1, 0) // without the control stream
	}
	return 0
}

// limitStream wraps s so that the first Close also calls release. A stream
// that is a net.Conn stays one, so callers keep the deadline methods.
func limitStream(s protocol.Stream, release func()) protocol.Stream {
	if conn, ok := s.(net.Conn); ok {
		return &limitedConn{Conn: conn, release: release}
	}
	return &limitedStream{Stream: s, release: release}
}

type limitedStream struct {
	protocol.Stream
	once    sync.Once
	release func()
}

func (l *limitedStream) Close() error {
	err := l.Stream.Close()
	l.once.Do(l.release)
	return err
}

// Shrink passes the call on to the wrapped stream (see edgeguard.Shrink).
func (l *limitedStream) Shrink() { edgeguard.Shrink(l.Stream) }

// SessionDone passes on the end of the wrapped stream's session (see
// edgeguard.SessionDone).
func (l *limitedStream) SessionDone() <-chan struct{} { return edgeguard.SessionDone(l.Stream) }

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (l *limitedConn) Close() error {
	err := l.Conn.Close()
	l.once.Do(l.release)
	return err
}

// Shrink passes the call on to the wrapped stream (see edgeguard.Shrink).
func (l *limitedConn) Shrink() { edgeguard.Shrink(l.Conn) }

// SessionDone passes on the end of the wrapped stream's session (see
// edgeguard.SessionDone).
func (l *limitedConn) SessionDone() <-chan struct{} { return edgeguard.SessionDone(l.Conn) }

// Close ends the session. The slots its streams hold in the user's limit are
// given back at once, whether or not the edges have closed those streams yet:
// with the session the streams are gone. Calling Close more than once is
// harmless.
func (t *TunnelSession) Close() error {
	_, err := t.shutDown()
	return err
}

// shutDown is Close; it also reports whether this call closed the session
// (false when it was closed already).
func (t *TunnelSession) shutDown() (closed bool, err error) {
	t.closeMu.Lock()
	select {
	case <-t.closed:
		t.closeMu.Unlock()
		return false, nil
	default:
	}
	close(t.closed)
	err = t.ymux.Close()
	t.closeMu.Unlock()
	if t.user != nil {
		t.user.leave(t)
	}
	return true, err
}

func (t *TunnelSession) Done() <-chan struct{} { return t.closed }

// sessionIDBytes is the amount of randomness in a session ID.
const sessionIDBytes = 16

// newSessionID returns a session ID of 16 random bytes in hex. It fails when
// the random source fails; the caller must not go on with a guessable ID.
func newSessionID(random io.Reader) (string, error) {
	var b [sessionIDBytes]byte
	if _, err := io.ReadFull(random, b[:]); err != nil {
		return "", fmt.Errorf("session id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
