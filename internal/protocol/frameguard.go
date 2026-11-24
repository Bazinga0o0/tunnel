package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// yamux answers every ping request (a ping frame with the SYN flag) from a
// goroutine of its own, which waits up to ConnectionWriteTimeout (10 s) when
// the answers cannot be sent (yamux v0.1.2 session.go handlePing). A peer
// that sends ping requests and does not read makes the server park one
// goroutine, about 9 KiB, per 12-byte frame: a few megabytes of pings take
// gigabytes, before the login as well as after it. The frame guard below
// sits between the connection and yamux on the server side, follows the
// yamux framing of the inbound bytes and ends the connection when the peer
// asks for more pings than an honest one does, or opens more streams.
//
// An honest client sends one ping request per keep-alive interval
// (DefaultKeepAliveInterval, yamux's keep-alive; nothing else in the client
// pings). The allowance is a token bucket of DefaultPingBurst requests that
// regains one every DefaultPingRefill: twice the keep-alive rate, with room
// for two at once. So at most MaxParkedPingAnswers (two) answers wait at a
// time, which the session's memory cost counts (acceptor.SessionMemoryBytes),
// and a peer that goes beyond the allowance loses its connection.
const (
	DefaultKeepAliveInterval = 30 * time.Second
	DefaultPingBurst         = 2
	DefaultPingRefill        = 15 * time.Second
)

// ConnectionWriteTimeout is yamux's ConnectionWriteTimeout on both sides: a
// frame waits at most this long to be handed to the session's send loop.
const ConnectionWriteTimeout = 10 * time.Second

// MaxParkedPingAnswers is the most ping answers that a server session can
// have waiting at a time under the default allowance: each waits at most
// ConnectionWriteTimeout, and within that time the bucket lets through at
// most DefaultPingBurst requests and one more per DefaultPingRefill.
const MaxParkedPingAnswers = DefaultPingBurst + int(ConnectionWriteTimeout/DefaultPingRefill)

// PingAnswerMemoryBytes is the memory of one ping answer that waits: its
// goroutine's stack, the frame and the timer. Measured
// (pingcost_measure_test.go, go1.27.4): 9.1 KiB; counted at 10 KiB.
const PingAnswerMemoryBytes = 10 << 10

// ErrTooManyPings ends a connection whose peer asked for more pings than the
// allowance. yamux then closes the session.
var ErrTooManyPings = errors.New("protocol: too many ping requests from the peer")

// A client opens exactly one stream, the control stream
// (internal/client/dialer opens it once per connection, and the tunnel
// command only accepts streams after that); every data stream is opened by
// the server. yamux registers a stream as soon as a frame with the SYN flag
// arrives and keeps it in the accept backlog with a receive window the peer
// may fill before anyone accepts it (session.go incomingStream). The frame
// guard counts the frames that open a stream and ends the connection at the
// first one beyond DefaultPeerStreams, before yamux sees it: nothing can sit
// in the backlog, whatever happens to the acceptor's own guard.
const DefaultPeerStreams = 1

// ErrSecondStream ends a connection whose peer opened more streams than
// allowed (DefaultPeerStreams). yamux then closes the session.
var ErrSecondStream = errors.New("protocol: the peer opened a second stream")

// The parts of the yamux framing the guard needs (yamux v0.1.2 const.go):
// a 12-byte header of version, type, flags, stream ID and length, all big
// endian; a data frame is followed by length bytes of payload, the other
// types by nothing (their length is a window delta, a ping ID or a go-away
// code). The SYN flag is the same bit for every type: on a ping it asks for
// an answer; on a data or window-update frame it opens a stream
// (handleStreamMessage calls incomingStream for either type). A peer answers
// a stream the other side opened with the ACK flag, never with SYN
// (stream.go sendFlags).
const (
	frameHeaderSize       = 12
	frameVersion          = 0
	frameTypeData         = 0
	frameTypeWindowUpdate = 1
	frameTypePing         = 2
	frameTypeGoAway       = 3
	flagPingSYN           = 1
	flagStreamSYN         = 1
)

// frameGuard counts the ping requests and the stream openings of the inbound
// byte stream and passes every byte through unchanged. It holds no payload:
// it only remembers how many payload bytes of the current data frame are
// still to come and the part of a header that a read split.
type frameGuard struct {
	r         io.Reader
	now       func() time.Time
	onPings   func() // called once, when the ping allowance is exceeded
	onStreams func() // called once, when the peer opens one stream too many
	pingsOff  bool   // no ping allowance
	maxOpens  int    // stream openings allowed; 0: no limit

	hdr  [frameHeaderSize]byte
	hdrN int    // bytes of the current header seen so far
	skip uint32 // payload bytes of the current data frame still to pass
	off  bool   // stopped counting at a frame yamux does not know

	capacity time.Duration // burst × refill
	refill   time.Duration // the cost of one ping request
	credit   time.Duration
	last     time.Time

	pings int // ping requests seen (tests)
	opens int // stream openings seen
	err   error
}

// newFrameGuard returns a guard with the ping allowance burst and refill and
// no limit on stream openings (see maxOpens).
func newFrameGuard(r io.Reader, burst int, refill time.Duration, now func() time.Time, onPings func()) *frameGuard {
	capacity := time.Duration(burst) * refill
	return &frameGuard{r: r, now: now, onPings: onPings, capacity: capacity, refill: refill, credit: capacity, last: now()}
}

// Read reads from the connection. When the bytes read hold one ping request
// more than the allowance, or one stream opening more than allowed, it
// returns none of them and ErrTooManyPings or ErrSecondStream, now and on
// every later call.
//
// Any error of the connection is kept as well: the read that brings it
// passes its bytes on (followed through the framing first), and every later
// read returns the error without reading again. yamux v0.1.2 swallows one
// read error: when the discard of a data frame for a stream it does not know
// fails, it logs the error and reads the next header (session.go
// handleStreamMessage). A connection that can be read again after an error,
// such as a timeout whose deadline is cleared right after it, would then let
// yamux parse the rest of the announced payload as frames while the guard
// still skipped it as payload, and ping requests in it would pass uncounted.
func (g *frameGuard) Read(p []byte) (int, error) {
	if g.err != nil {
		return 0, g.err
	}
	n, err := g.r.Read(p)
	if n > 0 && !g.off {
		if e := g.scan(p[:n]); e != nil {
			g.err = e
			report := g.onPings
			if e == ErrSecondStream {
				report = g.onStreams
			}
			if report != nil {
				report()
			}
			return 0, e
		}
	}
	if err != nil {
		g.err = err
	}
	return n, err
}

// scan follows the framing through b.
func (g *frameGuard) scan(b []byte) error {
	for len(b) > 0 && !g.off {
		if g.skip > 0 {
			k := uint32(len(b))
			if k > g.skip {
				k = g.skip
			}
			b = b[k:]
			g.skip -= k
			continue
		}
		k := copy(g.hdr[g.hdrN:], b)
		g.hdrN += k
		b = b[k:]
		if g.hdrN < frameHeaderSize {
			return nil
		}
		g.hdrN = 0
		version, typ := g.hdr[0], g.hdr[1]
		if version != frameVersion || typ > frameTypeGoAway {
			// yamux refuses this and ends the session; nothing to count.
			g.off = true
			return nil
		}
		flags := binary.BigEndian.Uint16(g.hdr[2:4])
		switch typ {
		case frameTypeData, frameTypeWindowUpdate:
			if typ == frameTypeData {
				g.skip = binary.BigEndian.Uint32(g.hdr[8:12])
			}
			if flags&flagStreamSYN != 0 {
				g.opens++
				if g.maxOpens > 0 && g.opens > g.maxOpens {
					return ErrSecondStream
				}
			}
		case frameTypePing:
			if flags&flagPingSYN != 0 && !g.pingsOff {
				g.pings++
				if !g.allow() {
					return ErrTooManyPings
				}
			}
		}
	}
	return nil
}

// allow takes one ping request out of the bucket.
func (g *frameGuard) allow() bool {
	now := g.now()
	if elapsed := now.Sub(g.last); elapsed > 0 {
		g.last = now
		if g.credit += elapsed; g.credit > g.capacity {
			g.credit = g.capacity
		}
	}
	if g.credit < g.refill {
		return false
	}
	g.credit -= g.refill
	return true
}

// guardedConn is the connection as yamux sees it on the server side.
type guardedConn struct {
	io.ReadWriteCloser
	guard *frameGuard
}

func (c guardedConn) Read(p []byte) (int, error) { return c.guard.Read(p) }
