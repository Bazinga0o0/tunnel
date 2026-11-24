package acceptor

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// measuredSessionBytes is what an idle authenticated session costs
// (cmd/tunneld/memory_measure_test.go, go1.27.4: 68.9 KiB).
const measuredSessionBytes = 69 << 10

// A client that stops reading lets the session's send queue fill; from then
// on every ping answer waits in a goroutine of its own, up to the connection
// write timeout. SessionMemoryBytes counts the answers that the ping
// allowance lets wait at a time, on top of the session itself.
func TestTheSessionCostCoversTheParkedPingAnswers(t *testing.T) {
	need := measuredSessionBytes + protocol.MaxParkedPingAnswers*protocol.PingAnswerMemoryBytes
	require.LessOrEqual(t, need, SessionMemoryBytes,
		"%d parked ping answers of %d KiB on top of %d KiB do not fit %d KiB",
		protocol.MaxParkedPingAnswers, protocol.PingAnswerMemoryBytes>>10, measuredSessionBytes>>10, SessionMemoryBytes>>10)

	// And the allowance still serves an honest client, which pings once per
	// keep-alive interval: it regains more than a ping costs in that time.
	require.Less(t, protocol.DefaultPingRefill, protocol.DefaultKeepAliveInterval)
	require.GreaterOrEqual(t, protocol.DefaultPingBurst, 2)
}
