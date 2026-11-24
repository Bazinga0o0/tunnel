package edgeguard

import (
	"context"
	"time"
)

// Bounds of the backoff that accept and read loops apply after an error.
const (
	BackoffMin = 5 * time.Millisecond
	BackoffMax = time.Second
)

// Backoff yields the delays of an exponential backoff: BackoffMin, doubling
// up to BackoffMax, and BackoffMin again after Reset. The zero value is ready
// to use. It is not safe for concurrent use; every loop owns its own.
type Backoff struct {
	next time.Duration
}

// Next returns the delay to wait now and advances the sequence.
func (b *Backoff) Next() time.Duration {
	d := max(b.next, BackoffMin)
	b.next = min(2*d, BackoffMax)
	return d
}

// Reset restarts the sequence. Loops call it after a success.
func (b *Backoff) Reset() {
	b.next = 0
}

// Sleep waits for the next delay. It returns false when ctx ends first.
func (b *Backoff) Sleep(ctx context.Context) bool {
	t := time.NewTimer(b.Next())
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
