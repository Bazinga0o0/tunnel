package edgeguard

import (
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

// Deadliner is a connection or stream whose pending and future reads and
// writes can be given a deadline.
type Deadliner interface {
	SetDeadline(time.Time) error
}

// Stream is a tunnel stream as the edges need it. The deadline is not an
// extra: idle timeouts (Idle) and ending a stream whose peer stays silent
// (Abort) only work through it.
type Stream interface {
	io.ReadWriteCloser
	Deadliner
}

// ErrNoDeadlines is returned by RequireDeadlines.
var ErrNoDeadlines = errors.New("edgeguard: tunnel stream has no SetDeadline")

// RequireDeadlines returns s as a Stream. A stream without SetDeadline, such
// as a wrapper that does not pass the method on, is closed and refused with
// ErrNoDeadlines: on such a stream the idle timeout and Abort would do
// nothing, and nothing would show it.
func RequireDeadlines(s io.ReadWriteCloser) (Stream, error) {
	if st, ok := s.(Stream); ok {
		return st, nil
	}
	_ = s.Close()
	return nil, ErrNoDeadlines
}

// Idle implements an idle timeout with deadlines: every Touch moves the
// deadline of all targets to now+timeout, so a blocked read or write on any
// of them fails once nothing has moved in either direction for that long.
//
// To keep the cost per read and write negligible, deadlines are moved at most
// once per step (an eighth of the timeout, at most one second). The effective
// timeout therefore lies between timeout-step and timeout.
//
// A nil *Idle is valid and does nothing; NewIdle returns nil for a timeout
// that is not positive.
type Idle struct {
	timeout time.Duration
	step    time.Duration
	targets []Deadliner
	last    atomic.Int64 // UnixNano of the last deadline move; 0 before the first
}

// NewIdle returns an Idle over the targets: the visitor connection and the
// tunnel stream.
func NewIdle(timeout time.Duration, targets ...Deadliner) *Idle {
	if timeout <= 0 {
		return nil
	}
	return &Idle{timeout: timeout, step: min(timeout/8, time.Second), targets: targets}
}

// Touch records activity.
func (i *Idle) Touch() {
	if i == nil {
		return
	}
	now := time.Now()
	if last := i.last.Load(); last != 0 && now.UnixNano()-last < int64(i.step) {
		return
	}
	i.last.Store(now.UnixNano())
	deadline := now.Add(i.timeout)
	for _, t := range i.targets {
		_ = t.SetDeadline(deadline)
	}
}

// Reader returns r wrapped so that every successful read counts as activity.
func (i *Idle) Reader(r io.Reader) io.Reader {
	if i == nil {
		return r
	}
	return idleReader{r: r, idle: i}
}

// Writer returns w wrapped so that every successful write counts as activity.
func (i *Idle) Writer(w io.Writer) io.Writer {
	if i == nil {
		return w
	}
	return idleWriter{w: w, idle: i}
}

// Abort closes s and makes its blocked and future reads and writes fail at
// once. Close alone is not enough to end a yamux stream: it only ends the
// local write side and keeps serving reads until the peer closes too.
func Abort(s interface {
	io.Closer
	Deadliner
}) {
	_ = s.Close()
	_ = s.SetDeadline(time.Unix(1, 0))
}

// Shrink lets a tunnel stream give back the memory of a receive buffer that
// is empty. A yamux stream keeps its buffer at the largest size a burst ever
// made it grow to, up to about twice the stream window, until the stream
// ends. Shrink does nothing for a stream without that method.
func Shrink(s any) {
	if sh, ok := s.(interface{ Shrink() }); ok {
		sh.Shrink()
	}
}

// SessionDone returns a channel that is closed when the tunnel session of
// stream s has ended, or nil when s cannot tell: a yamux stream gives its
// session's CloseChan, a wrapper passes it on with a SessionDone method.
// After that nothing more can arrive on the stream.
func SessionDone(s any) <-chan struct{} {
	switch v := s.(type) {
	case interface{ SessionDone() <-chan struct{} }:
		return v.SessionDone()
	case interface{ Session() *yamux.Session }:
		if sess := v.Session(); sess != nil {
			return sess.CloseChan()
		}
	}
	return nil
}

type idleReader struct {
	r    io.Reader
	idle *Idle
}

func (r idleReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.idle.Touch()
	}
	return n, err
}

type idleWriter struct {
	w    io.Writer
	idle *Idle
}

func (w idleWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		w.idle.Touch()
	}
	return n, err
}
