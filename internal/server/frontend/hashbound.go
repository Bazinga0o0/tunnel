package frontend

import (
	"net/http"
	"sync"
	"time"
)

// Texts and hint of the answer to a client that has Options.HashPerIP
// requests with password-hash work in flight already. They depend on the
// client's address only, never on an account.
const (
	msgHashBusy      = "Too many password checks from your network at the same time. Please try again in a moment."
	msgHashBusyAdmin = "Too many password checks from your network at the same time. Try again in a moment. Nothing was changed."
	// hashBusyRetryAfter is the Retry-After of that answer: a slot is free
	// again as soon as one of the client's own requests is done.
	hashBusyRetryAfter = time.Second
)

// hashBound bounds the requests with password-hash work that one client
// (sourceKey) has in flight at the same time.
//
// The table holds one entry per client that has such a request in flight,
// with the number of them, and drops the entry when that number returns to
// zero; it cannot grow beyond the number of requests in flight. On top of
// that it holds at most maxKeys entries: when it is full, a client without
// an entry is refused like a client over its bound (each entry stands for a
// request that holds or waits for one of the few process-wide hash slots, so
// a full table means those slots are taken anyway).
type hashBound struct {
	limit   int // <= 0: no bound, nothing is recorded
	maxKeys int // <= 0: no cap on the number of entries

	mu       sync.Mutex
	inFlight map[string]int
}

func newHashBound(limit, maxKeys int) *hashBound {
	return &hashBound{limit: limit, maxKeys: maxKeys, inFlight: map[string]int{}}
}

// take takes one of key's slots. When key has limit slots taken, or the
// table is full and key has none, it returns ok false and takes nothing.
// Otherwise the caller must call release when the hash work is done; release
// gives the slot back on its first call and does nothing on later ones.
func (b *hashBound) take(key string) (release func(), ok bool) {
	if b.limit <= 0 {
		return func() {}, true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	n := b.inFlight[key]
	if n >= b.limit {
		return nil, false
	}
	if n == 0 && b.maxKeys > 0 && len(b.inFlight) >= b.maxKeys {
		return nil, false
	}
	b.inFlight[key] = n + 1
	var once sync.Once
	return func() { once.Do(func() { b.giveBack(key) }) }, true
}

func (b *hashBound) giveBack(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n := b.inFlight[key]; n > 1 {
		b.inFlight[key] = n - 1
	} else {
		delete(b.inFlight, key)
	}
}

// size returns the number of clients with hash work in flight.
func (b *hashBound) size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.inFlight)
}

// takeHashSlot takes one of the client's slots for password-hash work
// (Options.HashPerIP), keyed like the other per-client limits (the peer
// address, IPv6 per /64). Every handler that hashes a password calls it
// before its first hash and defers release; the slot covers every hash of
// the request. When the client has no slot left it sets Retry-After and
// returns ok false: the caller answers 429 at once, without waiting for a
// slot and without counting against any rate limit.
func (o Options) takeHashSlot(w http.ResponseWriter, r *http.Request) (release func(), ok bool) {
	release, ok = o.limiters.hashes.take(sourceKey(clientIP(r)))
	if !ok {
		setRetryAfter(w, hashBusyRetryAfter)
		return func() {}, false
	}
	return release, true
}
