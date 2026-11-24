package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A read error must end what yamux reads, not only the read it came with.
// yamux v0.1.2 swallows one error: when the discard of a data frame for a
// stream it does not know fails (session.go handleStreamMessage), it logs
// the error and reads the next header. If the connection reads again after
// the error (a timeout whose deadline was cleared right after it, as the
// acceptor does at the end of the login), yamux would parse the rest of the
// announced payload as frames while the guard still skips it as payload:
// ping requests would pass uncounted.

// scriptConn is the server end of a connection whose reads follow a script.
// Each step hands out its bytes, and its error with the last of them; when
// the script is used up, a read waits until the connection is closed. Reads
// after an error go on with the next step, as a connection does whose read
// deadline was cleared after it expired. What the server writes is kept.
type scriptConn struct {
	mu     sync.Mutex
	steps  []scriptStep
	reads  int // reads that reached the script
	out    bytes.Buffer
	closed chan struct{}
	once   sync.Once
}

type scriptStep struct {
	b   []byte
	err error
}

func newScriptConn(steps ...scriptStep) *scriptConn {
	return &scriptConn{steps: steps, closed: make(chan struct{})}
}

func (c *scriptConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	c.reads++
	if len(c.steps) == 0 {
		c.mu.Unlock()
		<-c.closed
		return 0, io.EOF
	}
	s := &c.steps[0]
	n := copy(p, s.b)
	s.b = s.b[n:]
	var err error
	if len(s.b) == 0 {
		err = s.err
		c.steps = c.steps[1:]
	}
	c.mu.Unlock()
	return n, err
}

func (c *scriptConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(p)
}

func (c *scriptConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *scriptConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.out.Bytes()...)
}

// pingAnswers counts the ping answers (ping frames with the ACK flag) in
// what a yamux session wrote.
func pingAnswers(b []byte) int {
	n := 0
	for len(b) >= frameHeaderSize {
		typ := b[1]
		flags := binary.BigEndian.Uint16(b[2:4])
		length := binary.BigEndian.Uint32(b[8:12])
		b = b[frameHeaderSize:]
		switch typ {
		case frameTypeData:
			b = b[min(int(length), len(b)):]
		case frameTypePing:
			if flags&2 != 0 { // ACK
				n++
			}
		}
	}
	return n
}

// timeout is the error of a read whose deadline expired.
var timeout = os.ErrDeadlineExceeded

func TestAReadErrorEndsTheSessionAndNoPingAfterItIsAnswered(t *testing.T) {
	pings := bytes.Repeat(pingSYN(7), 50) // far beyond the allowance of 8
	// A data frame for a stream yamux does not know, announcing more payload
	// than will ever come; yamux discards it.
	unknown := frame(frameTypeData, 0, 99, 100000, nil)
	payload := bytes.Repeat([]byte{0xAB}, 64)
	for _, tc := range []struct {
		name  string
		steps []scriptStep
	}{
		{"a timeout inside the payload", []scriptStep{
			{b: append(append([]byte(nil), unknown...), payload...)},
			{err: timeout},
			{b: pings},
		}},
		{"payload bytes together with the timeout", []scriptStep{
			{b: append(append([]byte(nil), unknown...), payload...)},
			{b: payload, err: timeout},
			{b: pings},
		}},
		{"a timeout on a frame boundary", []scriptStep{
			{b: dataFrame(99, payload)},
			{err: timeout},
			{b: pings},
		}},
		{"the end of the stream inside the payload", []scriptStep{
			{b: append(append([]byte(nil), unknown...), payload...)},
			{err: io.EOF},
			{b: pings},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newScriptConn(tc.steps...)
			sess, err := NewServerSessionWithOptions(conn, ServerOptions{})
			require.NoError(t, err)
			defer sess.Close()

			ended := make(chan struct{})
			go func() {
				defer close(ended)
				for {
					if _, err := sess.AcceptStream(); err != nil {
						return
					}
				}
			}()
			select {
			case <-ended:
			case <-time.After(5 * time.Second):
				t.Fatal("the session goes on after the read error")
			}
			time.Sleep(50 * time.Millisecond) // answers that are on their way
			assert.Zero(t, pingAnswers(conn.written()), "ping requests after the read error were answered")
		})
	}
}

// failingReader returns its bytes together with err once, and counts the
// reads that reach it.
type failingReader struct {
	b     []byte
	err   error
	calls int
}

func (f *failingReader) Read(p []byte) (int, error) {
	f.calls++
	if f.calls > 1 {
		return copy(p, pingSYN(1)), nil // what a cleared deadline would let through
	}
	return copy(p, f.b), f.err
}

// The guard keeps the first error of the connection and returns it on every
// later read without reading again; the bytes of the read that came with the
// error are passed on and followed through the framing first.
func TestPingGuardKeepsTheReadError(t *testing.T) {
	for _, err := range []error{timeout, io.EOF, errors.New("connection reset")} {
		head := frame(frameTypeData, 0, 99, 100, nil)
		r := &failingReader{b: append(head, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10), err: err}
		g, _ := guardOver(r, 8)
		buf := make([]byte, 4096)
		n, got := g.Read(buf)
		assert.Equal(t, 22, n, "the bytes of the read are passed on")
		assert.ErrorIs(t, got, err)
		assert.EqualValues(t, 90, g.skip, "and followed through the framing")
		for i := 0; i < 3; i++ {
			n, got = g.Read(buf)
			assert.Zero(t, n)
			assert.ErrorIs(t, got, err, "the error is kept")
		}
		assert.Equal(t, 1, r.calls, "the connection is not read again after its error")
	}
}
