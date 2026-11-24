package protocol

// The measurement behind the cost of a parked ping answer (see the ping
// guard and acceptor.SessionMemoryBytes). It is not part of the normal test
// run: set TUNNELD_MEASURE_MEMORY=1 to run it, for example
//
//	TUNNELD_MEASURE_MEMORY=1 go test -count=1 -run '^TestMeasurePingAnswerCost$' -v ./internal/protocol/

import (
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// yamux answers a ping request from a goroutine of its own, which waits up
// to ConnectionWriteTimeout to hand the answer to the send loop. When the
// peer does not read, the send loop blocks, its queue (64 frames) fills up
// and every further answer parks its goroutine. This measures what one
// parked answer costs: the session runs without the guard, the peer sends
// ping requests and reads nothing.
func TestMeasurePingAnswerCost(t *testing.T) {
	if os.Getenv("TUNNELD_MEASURE_MEMORY") == "" {
		t.Skip("set TUNNELD_MEASURE_MEMORY=1 to measure the cost of a parked ping answer")
	}
	a, b := net.Pipe()
	server, err := NewServerSessionWithOptions(a, ServerOptions{PingBurst: -1})
	require.NoError(t, err)
	defer server.Close()
	defer b.Close()

	send := func(n int, from uint32) {
		for i := uint32(0); i < uint32(n); i++ {
			_, err := b.Write(pingSYN(from + i))
			require.NoError(t, err)
		}
	}
	// Fill the send loop's queue first, so that what follows parks.
	send(200, 1)
	time.Sleep(200 * time.Millisecond)

	sample := func() (heap, stack uint64, goroutines int) {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc, m.StackInuse, runtime.NumGoroutine()
	}
	h0, s0, g0 := sample()
	const parked = 2000
	send(parked, 1000)
	time.Sleep(200 * time.Millisecond)
	h1, s1, g1 := sample()
	t.Logf("%d more goroutines; per parked answer: heap %.1f KiB, stack %.1f KiB, total %.1f KiB",
		g1-g0, float64(h1-h0)/parked/1024, float64(s1-s0)/parked/1024, float64(h1-h0+s1-s0)/parked/1024)
}
