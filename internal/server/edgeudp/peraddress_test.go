package edgeudp

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/require"
)

// A stream that lingers after its flow has ended was caused by the flow's
// source address and keeps counting against it. With the defaults (64 flows
// per address and port): one address with 64 lingering flow streams on a
// port is refused its next flow there, while another address is admitted
// there and the same address on another port; once one of its streams is
// gone, the address is admitted again.
func TestOneAddressCanKeepAtMost64FlowStreamsOfAPortLingering(t *testing.T) {
	server, client := lingerPair(t, time.Minute)
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40030, 40031), IdleTimeout: 200 * time.Millisecond,
		SweepInterval: 20 * time.Millisecond})
	feeds := map[int]chan<- datagram{}
	mgr.listen = func(port int) (packetConn, error) {
		conn, feed := feedSocket(t)
		feeds[port] = feed
		return conn, nil
	}
	port1, err := mgr.Open(context.Background(), 0, yamuxOpener{server})
	require.NoError(t, err)
	defer mgr.Close(port1)
	port2, err := mgr.Open(context.Background(), 0, yamuxOpener{server})
	require.NoError(t, err)
	defer mgr.Close(port2)

	// 64 flows of one address, each from another port of it; each sends one
	// datagram and idles out, the tunnel client keeps each stream open.
	var lingering []*yamux.Stream
	for i := 0; i < DefaultMaxFlowsPerIP; i++ {
		msg := fmt.Sprintf("flow %d", i)
		feeds[port1] <- datagram{[]byte(msg), netip.MustParseAddrPort(fmt.Sprintf("192.0.2.1:%d", 4000+i))}
		lingering = append(lingering, acceptClient(t, client, msg))
	}
	require.Eventually(t, func() bool { return mgr.limiter.Visitors() == 0 }, 6*time.Second, 5*time.Millisecond)
	require.Equal(t, DefaultMaxFlowsPerIP, mgr.limiter.Total())

	refused := requestCount(t, "limit_ip")
	feeds[port1] <- datagram{[]byte("one more"), netip.MustParseAddrPort("192.0.2.1:5000")}
	require.Eventually(t, func() bool { return requestCount(t, "limit_ip") == refused+1 }, 6*time.Second, 5*time.Millisecond,
		"the address's 65th flow on the port was not refused")

	feeds[port1] <- datagram{[]byte("another address"), netip.MustParseAddrPort("192.0.2.2:4000")}
	acceptClient(t, client, "another address").Close()
	feeds[port2] <- datagram{[]byte("another port"), netip.MustParseAddrPort("192.0.2.1:4000")}
	acceptClient(t, client, "another port").Close()

	// One lingering stream is gone: the address is admitted again.
	require.NoError(t, lingering[0].Close())
	require.Eventually(t, func() bool { return mgr.limiter.Total() == DefaultMaxFlowsPerIP-1 }, 6*time.Second, 5*time.Millisecond)
	feeds[port1] <- datagram{[]byte("admitted again"), netip.MustParseAddrPort("192.0.2.1:6000")}
	acceptClient(t, client, "admitted again").Close()

	for _, st := range lingering[1:] {
		_ = st.Close()
	}
	require.Eventually(t, func() bool { return mgr.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)
}
