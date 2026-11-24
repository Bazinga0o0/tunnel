package edgeguard

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBudgetIsSharedByLimiters(t *testing.T) {
	budget := NewBudget(3)
	a := NewLimiter(10, 10, 10)
	b := NewLimiter(2, 10, 10)
	a.SetBudget(budget)
	b.SetBudget(budget)
	src := netip.MustParseAddr("192.0.2.1")

	a1, err := a.Acquire("t", src)
	require.NoError(t, err)
	a2, err := a.Acquire("t", src)
	require.NoError(t, err)
	b1, err := b.Acquire("u", src)
	require.NoError(t, err)
	require.Equal(t, 3, budget.Used())

	// The budget is spent: both limiters refuse, under the label of the total.
	_, err = a.Acquire("t", src)
	require.ErrorIs(t, err, ErrLimitTotal)
	require.Equal(t, "limit_total", LimitLabel(err))
	_, err = b.Acquire("other", netip.MustParseAddr("192.0.2.2"))
	require.ErrorIs(t, err, ErrLimitTotal)
	require.Equal(t, 3, budget.Used(), "a refused slot takes nothing from the budget")
	require.Equal(t, 2, a.Total())
	require.Equal(t, 1, b.Total())

	// A slot released in one limiter is free for the other. Releasing twice
	// gives one slot back, not two.
	a1()
	a1()
	require.Equal(t, 2, budget.Used())
	b2, err := b.Acquire("u", src)
	require.NoError(t, err)
	require.Equal(t, 3, budget.Used())

	// The limiter's own total keeps applying while the budget has room.
	a2()
	require.Equal(t, 2, budget.Used())
	_, err = b.Acquire("u", src)
	require.ErrorIs(t, err, ErrLimitTotal, "b allows two of its own")
	require.Equal(t, 2, budget.Used())

	b1()
	b2()
	require.Zero(t, budget.Used())
	require.Zero(t, a.Total())
	require.Zero(t, b.Total())
}

// A slot refused by a per-tunnel or per-source limit is not charged to the
// budget and not left there.
func TestBudgetIsNotChargedForRefusedSlots(t *testing.T) {
	budget := NewBudget(10)
	l := NewLimiter(0, 2, 1)
	l.SetBudget(budget)
	one, two := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")

	r1, err := l.Acquire("t", one)
	require.NoError(t, err)
	_, err = l.Acquire("t", one)
	require.ErrorIs(t, err, ErrLimitSource)
	r2, err := l.Acquire("t", two)
	require.NoError(t, err)
	_, err = l.Acquire("t", netip.MustParseAddr("192.0.2.3"))
	require.ErrorIs(t, err, ErrLimitTunnel)
	require.Equal(t, 2, budget.Used())

	r1()
	r2()
	require.Zero(t, budget.Used())
}

func TestBudgetWithoutMaxOnlyCounts(t *testing.T) {
	for _, max := range []int{0, -1} {
		budget := NewBudget(max)
		l := NewLimiter(0, 0, 0)
		l.SetBudget(budget)
		var releases []func()
		for i := 0; i < 100; i++ {
			r, err := l.Acquire("t", netip.Addr{})
			require.NoError(t, err)
			releases = append(releases, r)
		}
		require.Equal(t, 100, budget.Used())
		for _, r := range releases {
			r()
		}
		require.Zero(t, budget.Used())
	}
}

// Without a budget a limiter is on its own, as before the type existed.
func TestLimiterWithoutBudget(t *testing.T) {
	l := NewLimiter(1, 0, 0)
	l.SetBudget(nil)
	r, err := l.Acquire("t", netip.Addr{})
	require.NoError(t, err)
	_, err = l.Acquire("t", netip.Addr{})
	require.ErrorIs(t, err, ErrLimitTotal)
	r()
	require.Zero(t, l.Total())
}

func TestBudgetConcurrentUse(t *testing.T) {
	const max = 7
	budget := NewBudget(max)
	limiters := []*Limiter{NewLimiter(0, 0, 0), NewLimiter(0, 0, 0), NewLimiter(0, 0, 0)}
	for _, l := range limiters {
		l.SetBudget(budget)
	}

	var held, peak, granted atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 24; g++ {
		wg.Add(1)
		go func(l *Limiter) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				release, err := l.Acquire("t", netip.Addr{})
				if err != nil {
					continue
				}
				granted.Add(1)
				n := held.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				if used := budget.Used(); used > max {
					t.Errorf("the budget reports %d used slots of %d", used, max)
				}
				held.Add(-1)
				release()
			}
		}(limiters[g%len(limiters)])
	}
	wg.Wait()

	require.LessOrEqual(t, peak.Load(), int64(max), "more slots were held at once than the budget has")
	require.Positive(t, granted.Load())
	require.Zero(t, budget.Used())
	for _, l := range limiters {
		require.Zero(t, l.Total())
	}
}
