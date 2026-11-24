package acceptor

import (
	"errors"
	"fmt"
	"sync"
)

// ErrTooManyUserStreams is returned by TunnelSession.OpenStream when the
// sessions of the session's user together carry the maximum number of data
// streams (Options.MaxStreamsPerUser). It wraps ErrTooManyStreams: the edges
// refuse the visitor the same way for either limit.
var ErrTooManyUserStreams = fmt.Errorf("%w: limit of the user's sessions reached", ErrTooManyStreams)

// errSessionEnded is returned by TunnelSession.OpenStream once the session
// has been closed.
var errSessionEnded = errors.New("tunnel session ended")

// userStreams bounds the data streams of all sessions of one user together.
//
// It holds a slot for every stream that TunnelSession.OpenStream has handed
// out and that has not been closed yet; each slot is taken once and given
// back once, on the stream's first Close or, for the slots a session still
// holds, when the session ends. A new stream is admitted only while the
// user's sessions carry fewer streams than the limit, where a session counts
// the larger of its slots and its live yamux streams: like the per-session
// limit, the user's limit counts the streams that the server has closed but
// the client keeps open, because those still hold their receive buffers.
//
// Sessions without a user (static-token mode) are not subject to it.
type userStreams struct {
	max int // greater than zero

	mu sync.Mutex
	// users maps a user to the slots each of its sessions holds. A session
	// is entered with its first stream and removed when it ends; a user
	// without sessions in the map is removed.
	users map[int64]map[*TunnelSession]int
}

func newUserStreams(max int) *userStreams {
	return &userStreams{max: max, users: map[int64]map[*TunnelSession]int{}}
}

// counted is what acquire knows about one session of the user: the slots it
// held when the snapshot was taken and its live streams, asked afterwards.
type counted struct {
	held, live int
}

// acquire takes a slot for a new stream of t. It fails with
// ErrTooManyUserStreams when the user's sessions carry max streams together,
// and with errSessionEnded when t has been closed. release gives the slot
// back; calling it more than once is harmless.
//
// The live streams of a session come from yamux, whose stream lock a peer
// that does not read can hold for up to the connection write timeout (10 s).
// So yamux is never asked while u.mu is held, the lock all users share:
// acquire takes a snapshot of the user's sessions under the lock, asks yamux
// without it, and admits under the lock again. A session that is stuck then
// delays only the opens of its own user, never another user's open, nor any
// Close.
//
// Under concurrency the admission can only count too many, never too few
// held slots: slots are taken and given back under the lock and the
// admission sees the current ones. A session's live streams are the count
// yamux gave at the time of asking, raised by the slots the session took
// since the snapshot; streams that ended meanwhile still count (too many,
// at most by what ended during one count), streams that the server closed
// and the client keeps open after the count are not seen until the next
// open (they were counted as held slots until their close).
func (u *userStreams) acquire(t *TunnelSession) (release func(), err error) {
	u.mu.Lock()
	// Close marks the session closed before it calls leave, which waits for
	// this lock: a session that has left is seen as closed here, so it is
	// never entered again.
	if isClosed(t) {
		u.mu.Unlock()
		return nil, errSessionEnded
	}
	snapshot := map[*TunnelSession]counted{t: {}}
	for s, held := range u.users[t.UserID] {
		snapshot[s] = counted{held: held}
	}
	u.mu.Unlock()

	for s, c := range snapshot {
		c.live = s.liveDataStreams() // yamux; may block on the peer
		snapshot[s] = c
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	if isClosed(t) {
		return nil, errSessionEnded
	}
	sessions := u.users[t.UserID]
	total := 0
	for s, held := range sessions {
		c, ok := snapshot[s]
		if !ok {
			total += held // entered after the snapshot: its slots at least
			continue
		}
		total += max(held, c.live+max(0, held-c.held))
	}
	if _, ok := sessions[t]; !ok {
		total += snapshot[t].live
	}
	if total >= u.max {
		return nil, ErrTooManyUserStreams
	}
	if sessions == nil {
		sessions = map[*TunnelSession]int{}
		u.users[t.UserID] = sessions
	}
	sessions[t]++
	var once sync.Once
	return func() { once.Do(func() { u.release(t) }) }, nil
}

// isClosed reports whether t has been closed.
func isClosed(t *TunnelSession) bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}

// release gives back one slot of t, unless t has left already and took its
// slots with it.
func (u *userStreams) release(t *TunnelSession) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if sessions := u.users[t.UserID]; sessions != nil {
		if held, ok := sessions[t]; ok && held > 0 {
			sessions[t] = held - 1
		}
	}
}

// leave removes t together with the slots it still holds. It is called when
// the session ends; calling it more than once is harmless.
func (u *userStreams) leave(t *TunnelSession) {
	u.mu.Lock()
	defer u.mu.Unlock()
	sessions := u.users[t.UserID]
	if sessions == nil {
		return
	}
	delete(sessions, t)
	if len(sessions) == 0 {
		delete(u.users, t.UserID)
	}
}

// held returns the number of slots the sessions of userID hold.
func (u *userStreams) held(userID int64) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, held := range u.users[userID] {
		n += held
	}
	return n
}
