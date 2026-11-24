package protocol

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Frames as a peer sends them (yamux v0.1.2): a stream is opened by the SYN
// flag on a window update (what OpenStream sends) or on a data frame (which
// yamux accepts as well); the peer answers a stream the server opened with
// the ACK flag.
const (
	testFlagSYN = 1
	testFlagACK = 2
	testFlagFIN = 4
)

func openStream(stream uint32) []byte {
	return frame(frameTypeWindowUpdate, testFlagSYN, stream, 0, nil)
}

// peerFrames is the inbound byte stream of an honest client: the control
// stream, data on it (some of which looks like stream-opening headers),
// answers to streams the server opened, pings, a FIN. With second, a second
// stream is opened at the returned offset, followed by more frames.
func peerFrames(second bool) (b []byte, secondAt int) {
	looksLikeOpen := append(openStream(9), frame(frameTypeData, testFlagSYN, 11, 0, nil)...)
	var s bytes.Buffer
	s.Write(openStream(1))
	s.Write(dataFrame(1, []byte("hello")))
	s.Write(dataFrame(1, bytes.Repeat(looksLikeOpen, 30)))
	s.Write(frame(frameTypeWindowUpdate, testFlagACK, 2, 1<<18, nil)) // the answer to a server stream
	s.Write(frame(frameTypeData, testFlagACK, 4, 3, []byte("abc")))   // the same, as a data frame
	s.Write(pingSYN(1))
	s.Write(frame(frameTypeWindowUpdate, 0, 1, 1<<17, nil))
	s.Write(frame(frameTypeData, testFlagFIN, 2, 0, nil))
	secondAt = -1
	if second {
		secondAt = s.Len()
		s.Write(frame(frameTypeData, testFlagSYN, 3, 4, []byte("more")))
		s.Write(openStream(5))
		s.Write(dataFrame(5, bytes.Repeat([]byte("x"), 100)))
	}
	s.Write(dataFrame(1, []byte("bye")))
	return s.Bytes(), secondAt
}

// streamGuardOver returns a guard over r that lets the peer open one stream.
func streamGuardOver(r io.Reader) (*frameGuard, *int) {
	trips := 0
	g, _ := guardOver(r, 100)
	g.maxOpens = 1
	g.onStreams = func() { trips++ }
	return g, &trips
}

// An honest client opens one stream: every byte passes, wherever the reads
// split the frames, and the guard counts exactly one opening.
func TestFrameGuardLetsTheControlStreamThroughAtEveryReadBoundary(t *testing.T) {
	want, _ := peerFrames(false)
	for size := 1; size <= 40; size++ {
		for _, sizes := range [][]int{{size}, {size, 1}, {1, size, 3}} {
			g, trips := streamGuardOver(&chunkReader{b: want, sizes: sizes})
			got, err := readAll(g)
			require.NoError(t, err, "chunks %v", sizes)
			require.Equal(t, want, got, "chunks %v: bytes changed", sizes)
			require.Zero(t, *trips, "chunks %v", sizes)
			require.Equal(t, 1, g.opens, "chunks %v: counted %d openings", sizes, g.opens)
		}
	}
}

// A second stream-opening frame ends the byte stream: the read that holds
// the end of its header returns none of its bytes, so yamux never sees the
// whole header and never registers the stream; the error stays.
func TestFrameGuardRefusesASecondStreamAtEveryReadBoundary(t *testing.T) {
	want, secondAt := peerFrames(true)
	for size := 1; size <= 40; size++ {
		for _, sizes := range [][]int{{size}, {size, 1}, {1, size, 3}} {
			g, trips := streamGuardOver(&chunkReader{b: want, sizes: sizes})
			got, err := readAll(g)
			require.ErrorIs(t, err, ErrSecondStream, "chunks %v", sizes)
			require.Equal(t, want[:len(got)], got, "chunks %v: bytes changed", sizes)
			require.Less(t, len(got), secondAt+frameHeaderSize, "chunks %v: the second opening's header passed", sizes)
			require.Equal(t, 1, *trips, "chunks %v: the trip is reported once", sizes)
			_, err = g.Read(make([]byte, 64))
			require.ErrorIs(t, err, ErrSecondStream, "chunks %v: and the reader stays closed", sizes)
			require.Equal(t, 1, *trips)
		}
	}
}

// Through a real session: a client that opens a second stream, and 32 more
// with data behind it, loses its connection before the server's session
// counts a second stream; nothing of the further streams reaches a buffer.
func TestAServerSessionCutsAClientThatOpensASecondStream(t *testing.T) {
	a, b := net.Pipe()
	var trips atomic.Int32
	server, err := NewServerSessionWithOptions(a, ServerOptions{OnStreamLimit: func() { trips.Add(1) }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	client, err := yamux.Client(b, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctrl, err := client.OpenStream()
	require.NoError(t, err)
	go func() { _, _ = ctrl.Write([]byte("hello")) }()
	sctrl, err := server.AcceptStream()
	require.NoError(t, err)
	buf := make([]byte, 5)
	_, err = io.ReadFull(sctrl, buf)
	require.NoError(t, err)

	window := make([]byte, 256<<10)
	for i := 0; i < 33; i++ {
		st, err := client.OpenStream()
		if err != nil {
			break // the server has cut the connection
		}
		go func() { _, _ = st.Write(window) }()
	}
	_, err = server.AcceptStream()
	require.ErrorIs(t, err, ErrSecondStream, "the session ended with the guard's error")
	assert.Equal(t, int32(1), trips.Load())
	assert.Equal(t, 1, server.(StreamCounter).NumStreams(), "only the control stream was ever registered")
}

// An honest session with streams the server opens (the client answers them
// with the ACK flag and closes them) is not cut. (The keep-alive pings are
// the ping rule's test.)
func TestAServerSessionLeavesAnHonestClientAlone(t *testing.T) {
	a, b := net.Pipe()
	var trips atomic.Int32
	server, err := NewServerSessionWithOptions(a, ServerOptions{OnStreamLimit: func() { trips.Add(1) }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	client, err := yamux.Client(b, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctrl, err := client.OpenStream()
	require.NoError(t, err)
	go func() { _, _ = ctrl.Write([]byte("hi")) }()
	_, err = server.AcceptStream()
	require.NoError(t, err)

	go func() {
		for {
			st, err := client.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(st, st) // echo, then the client's FIN
				_ = st.Close()
			}()
		}
	}()
	for i := 0; i < 20; i++ {
		st, err := server.OpenStream()
		require.NoError(t, err)
		_, err = st.Write([]byte("ping"))
		require.NoError(t, err)
		got := make([]byte, 4)
		_, err = io.ReadFull(st, got)
		require.NoError(t, err)
		require.NoError(t, st.Close())
	}
	time.Sleep(100 * time.Millisecond) // the client's last FINs arrive
	assert.Zero(t, trips.Load())
	_, err = server.OpenStream()
	require.NoError(t, err, "the session is still up")
}
