package acceptor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// expiringConn is the server end of a pipe whose handshake deadline expires
// by hand, at the worst moment: when the acceptor clears the deadline after
// the HelloAck, the read that yamux has pending fails with a timeout first,
// as it does when the deadline expires a moment before it is cleared.
type expiringConn struct {
	net.Conn
	ready int64 // bytes yamux must have read before the expiry is triggered

	mu      sync.Mutex
	read    int64
	pending bool
	expired chan struct{} // closed when a read failed with the expiry
	cleared chan struct{} // closed when the deadline was cleared afterwards
	once    sync.Once
}

func newExpiringConn(c net.Conn, ready int) *expiringConn {
	return &expiringConn{Conn: c, ready: int64(ready), expired: make(chan struct{}), cleared: make(chan struct{})}
}

func (c *expiringConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	c.pending = true
	c.mu.Unlock()
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.pending = false
	c.read += int64(n)
	c.mu.Unlock()
	if errors.Is(err, os.ErrDeadlineExceeded) {
		// The acceptor clears the deadline right after it expired: before
		// yamux reads again.
		_ = c.Conn.SetDeadline(time.Time{})
		c.once.Do(func() { close(c.expired) })
	}
	return n, err
}

func (c *expiringConn) SetDeadline(t time.Time) error {
	if !t.IsZero() {
		return c.Conn.SetDeadline(t)
	}
	// yamux has read what the client sent and waits for more.
	for wait := time.Now().Add(5 * time.Second); time.Now().Before(wait); time.Sleep(time.Millisecond) {
		c.mu.Lock()
		ready := c.pending && c.read >= c.ready
		c.mu.Unlock()
		if ready {
			break
		}
	}
	_ = c.Conn.SetReadDeadline(time.Unix(1, 0)) // the deadline expires ...
	select {
	case <-c.expired:
	case <-time.After(5 * time.Second):
	}
	err := c.Conn.SetDeadline(time.Time{}) // ... and is cleared right after
	close(c.cleared)
	return err
}

// yamuxFrame builds one yamux frame.
func yamuxFrame(typ uint8, flags uint16, stream, length uint32, payload []byte) []byte {
	b := make([]byte, 12, 12+len(payload))
	b[1] = typ
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint32(b[4:8], stream)
	binary.BigEndian.PutUint32(b[8:12], length)
	return append(b, payload...)
}

// lockedBytes collects what the server writes.
type lockedBytes struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBytes) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBytes) pingAnswers() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for b := l.b.Bytes(); len(b) >= 12; {
		typ, flags, length := b[1], binary.BigEndian.Uint16(b[2:4]), binary.BigEndian.Uint32(b[8:12])
		b = b[12:]
		switch typ {
		case 0: // data
			b = b[min(int(length), len(b)):]
		case 2: // ping
			if flags&2 != 0 { // ACK
				n++
			}
		}
	}
	return n
}

// The scenario end to end. A client logs in and, before
// the HelloAck, starts a data frame for a stream yamux does not know whose
// payload never comes; yamux waits in the discard of that payload. The
// handshake deadline expires in that read and is cleared right after. yamux
// swallows that one error and reads on, so without the guard keeping the
// error, the ping requests that follow would be parsed by yamux as frames
// while the guard skipped them as payload, and every one would be answered.
// The connection has to end instead, without an answer.
func TestADeadlineThatExpiresInsideAPayloadDoesNotLetPingsPass(t *testing.T) {
	opts := staticOpts()
	opts.Registry = registry.New()
	logger, _ := captureLogger()
	opts.Logger = logger
	acc := New(opts)
	ln := newPipeListener()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = acc.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		<-done
	})

	var hello bytes.Buffer
	require.NoError(t, writeEnvelope(&hello, protocol.TypeHello, protocol.Hello{Token: staticToken, ClientVersion: "test", OS: "test"}))
	var login bytes.Buffer
	login.Write(yamuxFrame(1, 1, 1, 0, nil))                                     // open stream 1 (window update, SYN)
	login.Write(yamuxFrame(0, 0, 1, uint32(hello.Len()), hello.Bytes()))         // the hello on it
	login.Write(yamuxFrame(0, 0, 99, 1_000_000, bytes.Repeat([]byte{0xAB}, 10))) // payload that never comes

	client, server := net.Pipe()
	defer client.Close()
	conn := newExpiringConn(server, login.Len())
	ln.conns <- conn

	out := &lockedBytes{}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		_, _ = io.Copy(out, client)
	}()
	_, err := client.Write(login.Bytes())
	require.NoError(t, err)
	select {
	case <-conn.cleared:
	case <-time.After(waitFor):
		t.Fatal("the acceptor did not clear the handshake deadline")
	}

	for i := uint32(1); i <= 50; i++ {
		_ = client.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := client.Write(pingRequest(i)); err != nil {
			break
		}
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
	}
	assert.Zero(t, out.pingAnswers(), "ping requests after the expired deadline were answered")
	select {
	case <-closed:
	case <-time.After(waitFor):
		t.Fatal("the connection goes on after the read error")
	}
}
