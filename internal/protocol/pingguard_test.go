package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// frame builds one yamux frame: the 12-byte header and, for a data frame,
// the payload.
func frame(typ uint8, flags uint16, stream, length uint32, payload []byte) []byte {
	b := make([]byte, 12, 12+len(payload))
	b[0] = 0 // version
	b[1] = typ
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint32(b[4:8], stream)
	binary.BigEndian.PutUint32(b[8:12], length)
	return append(b, payload...)
}

func pingSYN(id uint32) []byte { return frame(frameTypePing, flagPingSYN, 0, id, nil) }

func dataFrame(stream uint32, payload []byte) []byte {
	return frame(frameTypeData, 0, stream, uint32(len(payload)), payload)
}

// chunkReader hands out its bytes in pieces of the given sizes, cycling.
type chunkReader struct {
	b     []byte
	sizes []int
	i     int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.b) == 0 {
		return 0, io.EOF
	}
	n := c.sizes[c.i%len(c.sizes)]
	c.i++
	n = min(n, len(p), len(c.b))
	copy(p, c.b[:n])
	c.b = c.b[n:]
	return n, nil
}

// guardOver returns a guard with a frozen clock over r: no refill.
func guardOver(r io.Reader, burst int) (*frameGuard, *int) {
	trips := 0
	now := time.Unix(1_700_000_000, 0)
	g := newFrameGuard(r, burst, time.Hour, func() time.Time { return now }, func() { trips++ })
	return g, &trips
}

// readAll reads g to its end and returns what came through and the error.
func readAll(g io.Reader) ([]byte, error) {
	var out bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := g.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			if err == io.EOF {
				return out.Bytes(), nil
			}
			return out.Bytes(), err
		}
	}
}

// The guard passes every byte through unchanged and counts exactly the ping
// requests, wherever the reads split the frames.
func TestPingGuardFollowsTheFramingAtEveryReadBoundary(t *testing.T) {
	looksLikePing := pingSYN(99) // a payload that is itself a ping header
	var stream bytes.Buffer
	stream.Write(dataFrame(1, []byte("hello")))
	stream.Write(dataFrame(3, nil)) // zero-length data frame
	stream.Write(pingSYN(1))
	stream.Write(dataFrame(1, bytes.Repeat(looksLikePing, 20)))
	stream.Write(frame(frameTypeWindowUpdate, 0, 1, 1<<18, nil)) // no payload despite the length
	stream.Write(frame(frameTypePing, 2 /* ACK */, 0, 7, nil))
	stream.Write(frame(frameTypeGoAway, 0, 0, 0, nil))
	stream.Write(pingSYN(2))
	stream.Write(dataFrame(5, append(bytes.Repeat([]byte{0}, 4093), looksLikePing...)))
	stream.Write(pingSYN(3))
	want := stream.Bytes()

	for size := 1; size <= 40; size++ {
		for _, sizes := range [][]int{{size}, {size, 1}, {1, size, 3}} {
			g, trips := guardOver(&chunkReader{b: want, sizes: sizes}, 3)
			got, err := readAll(g)
			require.NoError(t, err, "chunks %v", sizes)
			require.Equal(t, want, got, "chunks %v: bytes changed", sizes)
			require.Zero(t, *trips, "chunks %v: three ping requests are within a burst of three", sizes)
			require.Equal(t, 3, g.pings, "chunks %v: counted %d ping requests", sizes, g.pings)
		}
	}
}

// One ping request more than the allowance ends the stream of bytes with an
// error, before the frame that exceeds it is handed on.
func TestPingGuardRefusesBeyondTheAllowance(t *testing.T) {
	var stream bytes.Buffer
	for i := uint32(1); i <= 5; i++ {
		stream.Write(pingSYN(i))
	}
	stream.Write(dataFrame(1, []byte("never")))
	g, trips := guardOver(&chunkReader{b: stream.Bytes(), sizes: []int{12}}, 4)
	got, err := readAll(g)
	require.ErrorIs(t, err, ErrTooManyPings)
	assert.Equal(t, stream.Bytes()[:4*12], got, "the four allowed pings pass, the fifth does not")
	assert.Equal(t, 1, *trips, "the trip is reported once")
	_, err = g.Read(make([]byte, 10))
	require.ErrorIs(t, err, ErrTooManyPings, "and the reader stays closed")
	assert.Equal(t, 1, *trips)
}

// The bucket refills: an honest peer's pings, spaced out, never trip it.
func TestPingGuardRefills(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var stream bytes.Buffer
	for i := uint32(1); i <= 100; i++ {
		stream.Write(pingSYN(i))
	}
	trips := 0
	g := newFrameGuard(&chunkReader{b: stream.Bytes(), sizes: []int{12}}, 2, time.Second,
		func() time.Time { now = now.Add(time.Second); return now }, func() { trips++ })
	_, err := readAll(g)
	require.NoError(t, err)
	assert.Zero(t, trips)
}

// The largest data frame and an unknown frame type: the guard follows the
// first and leaves the second to yamux, which refuses it.
func TestPingGuardLargestFrameAndUnknownTypes(t *testing.T) {
	g, _ := guardOver(bytes.NewReader(nil), 1)
	require.NoError(t, g.scan(frame(frameTypeData, 0, 1, 0xFFFFFFFF, nil)))
	assert.EqualValues(t, 0xFFFFFFFF, g.skip)
	require.NoError(t, g.scan(bytes.Repeat([]byte{1}, 4096)))
	assert.EqualValues(t, 0xFFFFFFFF-4096, g.skip)

	g, trips := guardOver(bytes.NewReader(nil), 1)
	require.NoError(t, g.scan(frame(9, 0, 0, 0, nil)))
	assert.True(t, g.off, "an unknown type stops the counting")
	require.NoError(t, g.scan(bytes.Repeat(pingSYN(1), 10)))
	assert.Zero(t, *trips, "after that yamux refuses the stream of bytes itself")

	g, _ = guardOver(bytes.NewReader(nil), 1)
	bad := pingSYN(1)
	bad[0] = 1 // version
	require.NoError(t, g.scan(bad))
	assert.True(t, g.off)
}

// pipePair returns a server session over the guard and a yamux client
// session with the given keep-alive interval, over an in-memory pipe.
func pipePair(t *testing.T, keepAlive time.Duration, opts ServerOptions) (Session, *yamux.Session) {
	t.Helper()
	a, b := net.Pipe()
	server, err := NewServerSessionWithOptions(a, opts)
	require.NoError(t, err)
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = keepAlive
	cfg.LogOutput = io.Discard
	client, err := yamux.Client(b, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return server, client
}

// An honest peer sends one ping per keep-alive interval. With the
// allowance scaled to the interval in production's ratio (DefaultPingRefill
// against DefaultKeepAliveInterval, a burst of DefaultPingBurst), a real
// yamux session runs many intervals without being cut.
func TestHonestKeepAlivesAreNotCut(t *testing.T) {
	const interval = 60 * time.Millisecond
	tripped := make(chan struct{}, 1)
	server, client := pipePair(t, interval, ServerOptions{
		PingBurst:   DefaultPingBurst,
		PingRefill:  interval * DefaultPingRefill / DefaultKeepAliveInterval,
		OnPingLimit: func() { tripped <- struct{}{} },
	})
	go func() {
		for {
			st, err := server.AcceptStream()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(st, st) }()
		}
	}()
	st, err := client.OpenStream()
	require.NoError(t, err)
	deadline := time.Now().Add(40 * interval)
	for time.Now().Before(deadline) {
		_, err := st.Write([]byte("ping"))
		require.NoError(t, err)
		buf := make([]byte, 4)
		_, err = io.ReadFull(st, buf)
		require.NoError(t, err, "the session was cut")
		time.Sleep(interval / 4)
	}
	select {
	case <-tripped:
		t.Fatal("the allowance tripped on keep-alives")
	default:
	}
	assert.False(t, client.IsClosed())
}

// pingsUntilCut feeds a guard with production's allowance one ping request
// every interval on a clock of its own and returns the number of the request
// that was refused, or 0 when all of them passed.
func pingsUntilCut(every time.Duration, pings int) int {
	now := time.Unix(1_700_000_000, 0)
	var stream bytes.Buffer
	for i := 1; i <= pings; i++ {
		stream.Write(pingSYN(uint32(i)))
	}
	g := newFrameGuard(&chunkReader{b: stream.Bytes(), sizes: []int{12}}, DefaultPingBurst, DefaultPingRefill,
		func() time.Time { return now }, nil)
	for i := 1; i <= pings; i++ {
		if _, err := g.Read(make([]byte, 12)); err != nil {
			return i
		}
		now = now.Add(every)
	}
	return 0
}

// The allowance with production's numbers: a peer that pings once per
// keep-alive interval is never cut, over a day of intervals, nor one that
// pings twice as often; one that pings a little more often than the bucket
// regains is cut, and within a few minutes.
func TestTheAllowanceKeepsHonestPeersAndCutsFasterOnes(t *testing.T) {
	day := int(24 * time.Hour / DefaultKeepAliveInterval)
	require.Zero(t, pingsUntilCut(DefaultKeepAliveInterval, day), "an honest peer was cut")
	require.Zero(t, pingsUntilCut(DefaultPingRefill, day), "a peer at the refill rate was cut")
	cut := pingsUntilCut(DefaultPingRefill*9/10, day)
	require.NotZero(t, cut, "a peer above the allowance was never cut")
	require.Less(t, time.Duration(cut)*DefaultPingRefill*9/10, 10*time.Minute, "cut only after %d pings", cut)
}

// A flood of ping requests ends the session.
func TestPingFloodEndsTheServerSession(t *testing.T) {
	a, b := net.Pipe()
	tripped := make(chan struct{}, 1)
	server, err := NewServerSessionWithOptions(a, ServerOptions{OnPingLimit: func() { tripped <- struct{}{} }})
	require.NoError(t, err)
	defer server.Close()
	go func() { _, _ = io.Copy(io.Discard, b) }() // read the answers, so nothing blocks
	var err2 error
	for i := uint32(1); i <= 100 && err2 == nil; i++ {
		_, err2 = b.Write(pingSYN(i))
	}
	select {
	case <-tripped:
	case <-time.After(5 * time.Second):
		t.Fatal("the flood was not noticed")
	}
	_, err = server.AcceptStream()
	require.ErrorIs(t, err, ErrTooManyPings, "the session is over, ended by the guard")
}
