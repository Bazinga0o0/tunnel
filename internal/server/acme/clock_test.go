package acme

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a clock that moves only when the test advances it. Every
// After call is reported on waits, so a test can see what the code waits for
// and then advance by exactly that.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []fakeWaiter
	waits   chan time.Duration
}

type fakeWaiter struct {
	at time.Time
	ch chan time.Time
}

// newFakeClock starts at now without its monotonic reading. Two times that
// both have one are subtracted by it, a time read back from the backoff
// marker (wall time only) by wall time. On Linux time.Now takes the two
// readings one after the other, so the two differences between the same
// instants can disagree by a few nanoseconds. With wall time only, every
// difference is exact.
func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now.Round(0), waits: make(chan time.Duration, 1000)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
	} else {
		c.waiters = append(c.waiters, fakeWaiter{at: c.now.Add(d), ch: ch})
	}
	c.mu.Unlock()
	c.waits <- d
	return ch
}

// Advance moves the clock and fires the waits that are due.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	kept := c.waiters[:0]
	for _, w := range c.waiters {
		if !w.at.After(c.now) {
			w.ch <- c.now
		} else {
			kept = append(kept, w)
		}
	}
	c.waiters = kept
}

// nextWait returns the duration of the next After call; it fails the test
// when none comes. The bound is real time, but only a failing test waits
// for it.
func (c *fakeClock) nextWait(t *testing.T) time.Duration {
	t.Helper()
	select {
	case d := <-c.waits:
		return d
	case <-time.After(10 * time.Second):
		t.Fatal("the code did not wait on the clock")
		return 0
	}
}
