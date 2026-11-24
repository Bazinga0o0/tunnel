package edgeguard

import (
	"bytes"
	"log/slog"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// countingStream counts the bytes the drain takes from a yamux stream.
type countingStream struct {
	*yamux.Stream
	taken atomic.Int64
}

func (c *countingStream) Read(p []byte) (int, error) {
	n, err := c.Stream.Read(p)
	c.taken.Add(int64(n))
	return n, err
}

// bufferCap returns the capacity of a yamux stream's receive buffer: what it
// holds in memory for the bytes the drain has not read.
func bufferCap(st *yamux.Stream) int {
	v := reflect.ValueOf(st).Elem().FieldByName("recvBuf")
	b := *(**bytes.Buffer)(unsafe.Pointer(v.UnsafeAddr()))
	if b == nil {
		return 0
	}
	return b.Cap()
}

// testPace is the default pace with its period scaled down in time: the
// same bytes (two windows at full speed, then half a window per period), the
// period 250 ms instead of 30 s. So every proportion of production holds,
// 120 times faster.
var testPace = func() DrainPace {
	p := DefaultDrainPace
	p.Period = 250 * time.Millisecond
	return p
}()

func (p DrainPace) rate() float64 { return float64(p.Burst) / p.Period.Seconds() }

// A client that keeps sending after the edge is done with its stream gets
// rid of the fast budget and then no more than the slow rate allows: the
// bytes the drain takes stay within Fast + Burst + rate × elapsed. The
// stream's buffer meanwhile stays within what the slot counts.
func TestAPacedDrainTakesNoMoreThanItsPace(t *testing.T) {
	defer SetDrainPaceForTesting(testPace)()
	server, client := retirePair(t, time.Minute)
	st, peer, _ := floodingStream(t, server, client)
	c := &countingStream{Stream: st}
	var released atomic.Int32
	start := time.Now()
	RetirePaced(c, func() { released.Add(1) }, slog.Default())

	largest := 0
	for time.Since(start) < 2*time.Second {
		time.Sleep(20 * time.Millisecond)
		elapsed := time.Since(start).Seconds()
		limit := float64(testPace.Fast+testPace.Burst+drainBufferBytes) + testPace.rate()*elapsed
		require.LessOrEqual(t, float64(c.taken.Load()), limit, "the drain took more than its pace after %.2f s", elapsed)
		largest = max(largest, bufferCap(st))
	}
	elapsed := time.Since(start).Seconds()
	require.GreaterOrEqual(t, float64(c.taken.Load()), float64(testPace.Fast)+testPace.rate()*(elapsed-0.5),
		"the drain read less than its pace allows")
	// The buffer may fill to the window while the drain reads slowly; with
	// yamux's growth up to about twice the window. edgetcp.ConnMemoryBytes
	// (704 KiB) counts that.
	t.Logf("largest buffer %d KiB", largest>>10)
	assert.LessOrEqual(t, largest, 2*protocol.StreamWindowBytes+64<<10)
	require.Zero(t, released.Load())
	require.NoError(t, peer.Close())
	require.Eventually(t, func() bool { return released.Load() == 1 }, testPace.GoneWithin(protocol.StreamWindowBytes)+time.Second,
		5*time.Millisecond)
}

// An answer that had less than the fast budget left when the visitor went
// ends at once: the slot comes back without waiting for the slow phase.
func TestAPacedDrainEndsAShortRestAtOnce(t *testing.T) {
	server, client := retirePair(t, time.Minute)
	accepted := make(chan *yamux.Stream, 1)
	go func() {
		st, _ := client.AcceptStream()
		accepted <- st
	}()
	st, err := server.OpenStream()
	require.NoError(t, err)
	_, err = st.Write([]byte("x"))
	require.NoError(t, err)
	peer := <-accepted
	require.NotNil(t, peer)

	released := make(chan struct{})
	RetirePaced(st, func() { close(released) }, slog.Default()) // the default pace
	start := time.Now()
	rest := make([]byte, DefaultDrainPace.Fast*3/4)
	_, err = peer.Write(rest)
	require.NoError(t, err)
	require.NoError(t, peer.Close())
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("the slot of a short rest did not come back")
	}
	require.Less(t, time.Since(start), time.Second)
}

// Once the stream is gone with a full window buffered (the client closed
// its side, or the session ended, right after filling the window), the slot
// comes back within the pace's bound.
func TestAPacedDrainGivesTheSlotBackWithinItsBound(t *testing.T) {
	bound := testPace.GoneWithin(protocol.StreamWindowBytes)
	for _, end := range []string{"the client closes its side", "the session ends"} {
		t.Run(end, func(t *testing.T) {
			defer SetDrainPaceForTesting(testPace)()
			server, client := retirePair(t, time.Minute)
			st, peer, _ := floodingStream(t, server, client)
			released := make(chan struct{})
			RetirePaced(st, func() { close(released) }, slog.Default())
			// Past the fast phase, with the allowance used up and the
			// window full.
			time.Sleep(time.Second)
			start := time.Now()
			switch end {
			case "the client closes its side":
				require.NoError(t, peer.Close())
			case "the session ends":
				require.NoError(t, server.Close())
			}
			select {
			case <-released:
			case <-time.After(bound + 2*time.Second):
				t.Fatal("the slot did not come back")
			}
			took := time.Since(start)
			t.Logf("slot back %v after the end; bound %v", took, bound)
			require.LessOrEqual(t, took, bound+300*time.Millisecond)
		})
	}
}

// Once the stream's tunnel session has ended nothing more can arrive on the
// stream: a paced drain in its slow phase reads what is left at full speed,
// so that the slot's places (on a subdomain or port that a new session may
// take over) come back at once, not after the pace's bound (about a minute
// at the default pace).
func TestAPacedDrainReadsTheRestAtFullSpeedOnceTheSessionHasEnded(t *testing.T) {
	server, client := retirePair(t, time.Minute)
	st, _, _ := floodingStream(t, server, client)
	released := make(chan struct{})
	RetirePaced(st, func() { close(released) }, slog.Default()) // the default pace
	// Past the fast phase (512 KiB), with the window buffered.
	time.Sleep(time.Second)
	select {
	case <-released:
		t.Fatal("released before the session ended")
	default:
	}
	start := time.Now()
	require.NoError(t, server.Close())
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("the drain of a dead session still reads at its pace")
	}
	require.Less(t, time.Since(start), time.Second)
	require.Equal(t, server.CloseChan(), SessionDone(st), "a yamux stream tells its session's end")
}

// The pacer never allows a read of nothing: an empty slice would make a
// yamux stream with bytes buffered return (0, nil), which the drain counts
// as a stall, and after maxDrainStalls the slot would be given back with the
// stream still in the session.
func TestThePacerNeverAllowsAnEmptyRead(t *testing.T) {
	p := newPacer(testPace, nil)
	p.fast = 3
	for _, limit := range []int{1, 2, drainBufferBytes} {
		for i := 0; i < 200; i++ {
			n := p.allow(limit)
			require.GreaterOrEqual(t, n, 1, "limit %d, read %d", limit, i)
			require.LessOrEqual(t, n, limit)
			p.took(n)
		}
	}
	// A bucket left with a fraction of a byte, or overdrawn by one.
	for _, tokens := range []float64{0.5, -1, 0} {
		p.tokens, p.last = tokens, time.Now()
		require.GreaterOrEqual(t, p.allow(drainBufferBytes), 1, "tokens %v", tokens)
	}
}

// The default pace: two windows at full speed, then half a window per 30 s
// (about 4.3 KiB/s). Once the stream is gone with a full window buffered, the
// slot is back within a minute (60 s plus one step of the slow phase).
func TestTheDefaultDrainPace(t *testing.T) {
	assert.Equal(t, 2*protocol.StreamWindowBytes, DefaultDrainPace.Fast)
	assert.Equal(t, protocol.StreamWindowBytes/2, DefaultDrainPace.Burst)
	assert.InDelta(t, 4.27, DefaultDrainPace.rate()/1024, 0.01, "KiB/s")
	assert.InDelta(t, 61, DefaultDrainPace.GoneWithin(protocol.StreamWindowBytes).Seconds(), 1)
	// The scaled pace of the tests keeps production's proportions.
	assert.Equal(t, DefaultDrainPace.Fast, testPace.Fast)
	assert.Equal(t, DefaultDrainPace.Burst, testPace.Burst)
	assert.Less(t, testPace.Period, DefaultDrainPace.Period)
}
