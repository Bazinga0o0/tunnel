package edgetcp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
)

// With Options.TotalBudget the connections of this edge and the slots that
// other edges hold in the same budget stay within one total.
func TestTotalBudgetIsSharedWithOtherEdges(t *testing.T) {
	pool, ports := testPorts(t, 1)
	budget := edgeguard.NewBudget(3)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, TotalBudget: budget})

	// Another edge holds two of the three slots.
	other := edgeguard.NewLimiter(0, 0, 0)
	other.SetBudget(budget)
	release1, err := other.Acquire("other", netip.Addr{})
	require.NoError(t, err)
	release2, err := other.Acquire("other", netip.Addr{})
	require.NoError(t, err)

	sess := newScriptSession()
	defer sess.closeBackends()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	before := requestCount(t, "limit_total")
	v1 := dial(t, port)
	b1, _ := acceptStream(t, sess)
	exchange(t, v1, b1, "one")
	require.Equal(t, 3, budget.Used())

	v2 := dial(t, port)
	expectClosed(t, v2, 6*time.Second, "connection beyond the shared budget")
	require.Equal(t, before+1, requestCount(t, "limit_total"))
	require.EqualValues(t, 1, sess.opens.Load(), "no stream is opened for a refused connection")
	require.Equal(t, 3, budget.Used())

	// A slot that the other edge gives back is available here.
	release1()
	v3 := dial(t, port)
	b3, _ := acceptStream(t, sess)
	exchange(t, v3, b3, "three")
	require.Equal(t, 3, budget.Used())

	// Connections that end return their slots to the budget.
	release2()
	mgr.Close(port)
	require.Eventually(t, func() bool { return budget.Used() == 0 }, 6*time.Second, 5*time.Millisecond)
}

// Without a budget the edge keeps its own total; with one, its own total
// still applies.
func TestTotalBudgetDoesNotReplaceMaxConns(t *testing.T) {
	pool, ports := testPorts(t, 1)
	budget := edgeguard.NewBudget(100)
	mgr := NewWithOptions(Options{BindHost: "127.0.0.1", Pool: pool, MaxConns: 1, TotalBudget: budget})
	sess := newScriptSession()
	defer sess.closeBackends()
	port, err := mgr.Open(context.Background(), ports[0], sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	before := requestCount(t, "limit_total")
	v1 := dial(t, port)
	b1, _ := acceptStream(t, sess)
	exchange(t, v1, b1, "one")

	v2 := dial(t, port)
	expectClosed(t, v2, 6*time.Second, "connection beyond MaxConns")
	require.Equal(t, before+1, requestCount(t, "limit_total"))
	require.Equal(t, 1, budget.Used())
}
