package frontend

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every table that counts requests is in the memory sum: a table added to
// rateLimiters without being added to tables() turns this test red.
func TestEveryCountingTableIsInTheMemorySum(t *testing.T) {
	typ := reflect.TypeOf(rateLimiters{})
	limiter := reflect.TypeOf((*rateLimiter)(nil))
	fields := 0
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type == limiter {
			fields++
		}
	}
	r := newRateLimiters(Options{})
	tables := r.tables()
	assert.Len(t, tables, fields)
	seen := map[*rateLimiter]bool{}
	for _, tb := range tables {
		require.NotNil(t, tb)
		assert.False(t, seen[tb], "a table is listed twice")
		seen[tb] = true
	}
}

// eventCapacity is the capacity append really gives a log that grows one
// request at a time.
func TestEventCapacityIsWhatAppendGives(t *testing.T) {
	var log []time.Time
	for n := 1; n <= 600; n++ {
		log = append(log, time.Time{})
		require.Equal(t, cap(log), eventCapacity(n), "after %d requests", n)
	}
	assert.Zero(t, eventCapacity(0))
	assert.Equal(t, 2*(maxSimulatedEvents+1), eventCapacity(maxSimulatedEvents+1))
}

func TestRateLimitBytesPerKey(t *testing.T) {
	cost := func(limit int) int64 {
		return RateLimitKeyBytes + RateLimitEventBytes*int64(eventCapacity(limit))
	}
	// The default tables and their limits.
	want := cost(DefaultLoginFailuresPerAccount) + cost(DefaultLoginFailuresPerIP) + cost(DefaultLoginsPerAccount) +
		cost(DefaultSignupsPerIP) + cost(DefaultResetRequestsPerIP) + 2*cost(DefaultResetRequestsPerAccount) +
		cost(1) + cost(DefaultUserActionsPerHour) + cost(DirectoryRequestsPerMinute)
	assert.Equal(t, want, RateLimitBytesPerKey(Options{}))

	// A table switched off costs nothing; a higher limit costs more.
	off := RateLimitBytesPerKey(Options{UserActionsPerHour: -1})
	assert.Equal(t, want-cost(DefaultUserActionsPerHour), off)
	more := RateLimitBytesPerKey(Options{LoginFailuresPerIP: 1000})
	assert.Equal(t, want-cost(DefaultLoginFailuresPerIP)+cost(1000), more)

	// An absurd limit makes the cost saturate instead of wrapping, possibly
	// to a negative number that the memory sum would take for no cost.
	assert.Equal(t, math.MaxInt, eventCapacity(math.MaxInt))
	assert.Equal(t, math.MaxInt, eventCapacity(math.MaxInt/2+1))
	assert.Equal(t, 2*(maxSimulatedEvents+1), eventCapacity(maxSimulatedEvents+1))
	for _, limit := range []int{math.MaxInt, math.MaxInt / 2, math.MaxInt / 24, 1 << 59} {
		assert.Equal(t, int64(math.MaxInt64), RateLimitBytesPerKey(Options{UserActionsPerHour: limit}), "limit %d", limit)
	}
}
