package frontend

import (
	"math"
	"time"
)

// Memory of the web UI's rate-limit tables, for the server's memory budget
// (cmd/tunneld/memory.go).
//
// A table keeps one entry per key (client address, typed account address or
// user) with the time of each counted request inside its window, at most the
// table's limit of them, and it holds at most RateLimitMaxKeys keys. Measured
// with ratelimit_memory_measure_test.go (go1.27.4, 20000 keys a table): 204
// to 213 bytes a key with one counted request, 572 with 10 (the limit of
// failed logins per account), 1076 to 1084 with 30 (the limit of failed
// logins per address and of successful logins), 4256 with 120 (the
// user-actions limit). A key costs about 188 bytes besides its log (the
// entry is 64 bytes: key, log, place in the order, the credit of the table
// of failed logins per account and a pointer to the state of its attempts
// in flight); the log is a slice of time.Time that grows the way append
// grows it (eventCapacity). Attempts in flight in the table of failed
// logins per account hold a little more (their pending events, and an
// entry for a key that has none yet) while they last; there are at most as
// many as requests in flight.

const (
	// RateLimitKeyBytes is the memory of one key besides its log of counted
	// requests: the entry, the key itself (32 bytes for an account, about 23
	// for an IPv6 /64), its place in the table's order and in its map, and
	// the allocation header of a large log. Measured 188; with margin 224.
	RateLimitKeyBytes = 224
	// RateLimitEventBytes is the memory of one slot of a key's log (a
	// time.Time).
	RateLimitEventBytes = 24
)

// maxSimulatedEvents bounds the logs whose capacity eventCapacity takes from
// append itself; beyond it the log grows by less than doubling, so twice the
// number of requests is an upper bound.
const maxSimulatedEvents = 1 << 16

// eventCapacity returns the number of slots a key's log holds after n counted
// requests: the capacity append gives a []time.Time that grows one request
// at a time (1, 2, 4, 8, 16, 37, 74, 170, … with go1.27: the size classes and
// the allocation header of large objects make it more than a power of two).
// It saturates at math.MaxInt for an absurd n.
func eventCapacity(n int) int {
	if n <= 0 {
		return 0
	}
	if n > maxSimulatedEvents {
		if n > math.MaxInt/2 {
			return math.MaxInt
		}
		return 2 * n
	}
	var log []time.Time
	for cap(log) < n {
		log = append(log[:cap(log)], time.Time{})
	}
	return cap(log)
}

// tables returns the rate-limit tables that count requests. The table of
// HashPerIP is not among them: it holds an entry only while a request of
// that client is doing hash work, so it never holds more entries than there
// are requests in flight.
func (r *rateLimiters) tables() []*rateLimiter {
	return []*rateLimiter{
		r.loginAccount, r.loginIP, r.logins, r.signupIP, r.resetIP,
		r.resetAccount, r.resetStored, r.resend, r.userActions, r.directory,
	}
}

// RateLimitBytesPerKey returns the most memory the rate-limit tables of a
// handler with these options hold per key of RateLimitMaxKeys: the sum over
// the tables of one key whose log is filled to the table's limit. A table
// whose limit is switched off records nothing and costs nothing. Each table
// holds at most RateLimitMaxKeys keys, so all of them together hold at most
// RateLimitMaxKeys times this. For table limits so large that the sum does
// not fit an int64 it returns math.MaxInt64 instead of a wrapped number.
func RateLimitBytesPerKey(o Options) int64 {
	var n int64
	for _, t := range newRateLimiters(o).tables() {
		if t.limit <= 0 {
			continue
		}
		events := int64(eventCapacity(t.limit))
		if events > (math.MaxInt64-RateLimitKeyBytes)/RateLimitEventBytes {
			return math.MaxInt64
		}
		key := RateLimitKeyBytes + RateLimitEventBytes*events
		if n > math.MaxInt64-key {
			return math.MaxInt64
		}
		n += key
	}
	return n
}
