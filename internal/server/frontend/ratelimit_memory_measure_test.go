package frontend

// The measurement behind RateLimitKeyBytes and RateLimitEventBytes. It is not
// part of the normal test run: set TUNNELD_MEASURE_MEMORY=1, for example
//
//	TUNNELD_MEASURE_MEMORY=1 go test -count=1 -run '^TestMeasureRateLimitMemory$' -v ./internal/server/frontend/
//
// It fills one limiter table with n keys, the way an attacker fills it (one
// counted request per key: a new address or a new typed account address per
// request) and the way that costs most per key (as many counted requests per
// key as the limit allows), and reports the live heap per key.

import (
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func heapAfterGC() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// accountKeyN is the key of the n-th typed account address, as accountKey
// makes it (32 bytes).
func accountKeyN(n int) string {
	sum := sha256.Sum256([]byte("user" + strconv.Itoa(n) + "@example.com"))
	return string(sum[:])
}

// addressKeyN is the key of the n-th IPv6 /64, as sourceKey makes it.
func addressKeyN(n int) string {
	return fmt.Sprintf("2001:db8:%x:%x::/64", n>>16, n&0xffff)
}

// measureTable returns the heap bytes per key of a table with keys keys and
// events counted requests per key.
func measureTable(limit, events, keys int, key func(int) string) float64 {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	base := heapAfterGC()
	l := newRateLimiter(limit, time.Hour, 0, clock)
	for i := 0; i < keys; i++ {
		k := key(i)
		for e := 0; e < events; e++ {
			if _, _, ok := l.take(k); !ok {
				panic("the limit refused an event below it")
			}
		}
	}
	after := heapAfterGC()
	if l.size() != keys {
		panic("the table lost keys")
	}
	runtime.KeepAlive(l)
	return (float64(after) - float64(base)) / float64(keys)
}

func TestMeasureRateLimitMemory(t *testing.T) {
	if os.Getenv("TUNNELD_MEASURE_MEMORY") == "" {
		t.Skip("set TUNNELD_MEASURE_MEMORY=1 to measure the memory of the rate-limit tables")
	}
	const keys = 20000
	t.Logf("%s %s/%s, %d keys per table", runtime.Version(), runtime.GOOS, runtime.GOARCH, keys)
	for _, c := range []struct {
		name          string
		limit, events int
		key           func(int) string
	}{
		{"one request per key, account keys (limit 30)", 30, 1, accountKeyN},
		{"one request per key, address keys (limit 30)", 30, 1, addressKeyN},
		{"limit 1, one request", 1, 1, accountKeyN},
		{"limit 3, three requests", 3, 3, accountKeyN},
		{"limit 5, five requests", 5, 5, addressKeyN},
		{"limit 10, ten requests", 10, 10, accountKeyN},
		{"limit 30, thirty requests, account keys", 30, 30, accountKeyN},
		{"limit 30, thirty requests, address keys", 30, 30, addressKeyN},
		{"limit 120, 120 requests (user keys)", 120, 120, func(n int) string { return strconv.Itoa(n + 1) }},
	} {
		per := measureTable(c.limit, c.events, keys, c.key)
		model := RateLimitKeyBytes + RateLimitEventBytes*int64(eventCapacity(c.events))
		t.Logf("%-46s %8.1f B/key   model %6d B/key", c.name, per, model)
		if per > float64(model) {
			t.Errorf("%s: measured %.1f B/key, more than the model's %d", c.name, per, model)
		}
	}
}
