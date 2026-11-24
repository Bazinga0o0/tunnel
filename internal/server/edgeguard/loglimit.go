package edgeguard

import (
	"sync"
	"time"
)

// LogInterval is the interval the edges use for warnings that an outside
// party can trigger at will, such as a failing OpenStream.
const LogInterval = 5 * time.Second

// LogLimiter lets one event per interval through and counts the ones it holds
// back, so that a repeated failure costs one log line per interval instead of
// one per request, connection or datagram.
type LogLimiter struct {
	interval time.Duration

	mu         sync.Mutex
	next       time.Time
	suppressed int
}

// NewLogLimiter returns a limiter that allows one event per interval.
func NewLogLimiter(interval time.Duration) *LogLimiter {
	return &LogLimiter{interval: interval}
}

// Allow reports whether the caller may log now. suppressed is the number of
// events held back since the last allowed one; callers add it to the line.
func (l *LogLimiter) Allow() (ok bool, suppressed int) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Before(l.next) {
		l.suppressed++
		return false, 0
	}
	l.next = now.Add(l.interval)
	suppressed, l.suppressed = l.suppressed, 0
	return true, suppressed
}
