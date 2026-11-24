package auth

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubKDF swaps the argon2 call for fn and returns a function that puts the
// real one back. Tests that use it must not run in parallel.
func stubKDF(fn func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte) (restore func()) {
	prev := argonIDKey
	argonIDKey = fn
	return func() { argonIDKey = prev }
}

// useHashLimits installs limits for one test and restores the defaults after.
func useHashLimits(t *testing.T, l HashLimits) {
	t.Helper()
	SetHashLimits(l)
	t.Cleanup(func() { SetHashLimits(HashLimits{}) })
}

// blockingKDF returns a KDF stub that parks every call until release is
// closed, and counters for the calls in flight.
type blockingKDF struct {
	inFlight atomic.Int32
	peak     atomic.Int32
	calls    atomic.Int32
	entered  chan struct{}
	release  chan struct{}
}

func newBlockingKDF() *blockingKDF {
	return &blockingKDF{entered: make(chan struct{}, 64), release: make(chan struct{})}
}

func (b *blockingKDF) fn(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
	n := b.inFlight.Add(1)
	for {
		p := b.peak.Load()
		if n <= p || b.peak.CompareAndSwap(p, n) {
			break
		}
	}
	b.calls.Add(1)
	b.entered <- struct{}{}
	<-b.release
	b.inFlight.Add(-1)
	return make([]byte, keyLen)
}

// waitEntered blocks until n KDF calls have started.
func (b *blockingKDF) waitEntered(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-b.entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d KDF calls started", i, n)
		}
	}
}

func TestHashLimitsZeroValueSelectsDefaults(t *testing.T) {
	useHashLimits(t, HashLimits{})
	g := gate.Load()
	require.NotNil(t, g)
	assert.Equal(t, 4, cap(g.slots), "default concurrency")
	assert.Equal(t, 5*time.Second, g.wait, "default wait")
	assert.Equal(t, 4, DefaultHashConcurrency)
	assert.Equal(t, 5*time.Second, DefaultHashWait)
}

func TestHashLimiterIsActiveWithoutAnySetup(t *testing.T) {
	// A process that never calls SetHashLimits must still be limited.
	g := gate.Load()
	require.NotNil(t, g, "limiter must be installed at package init")
	assert.Equal(t, DefaultHashConcurrency, cap(g.slots))
}

func TestHashLimiterBoundsConcurrentHashes(t *testing.T) {
	useHashLimits(t, HashLimits{MaxConcurrent: 2, MaxWait: 5 * time.Second})
	kdf := newBlockingKDF()
	defer stubKDF(kdf.fn)()

	const callers = 8
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := HashPasswordContext(context.Background(), "pw12345678")
			errs <- err
		}()
	}

	// Two calls reach the KDF; the other six must be parked at the gate.
	kdf.waitEntered(t, 2)
	time.Sleep(100 * time.Millisecond)
	assert.EqualValues(t, 2, kdf.inFlight.Load(), "calls inside the KDF while the gate is full")

	close(kdf.release)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.EqualValues(t, callers, kdf.calls.Load(), "every caller eventually hashed")
	assert.EqualValues(t, 2, kdf.peak.Load(), "peak concurrency equals the limit")
}

func TestHashLimiterReturnsErrBusyWhenNoSlotFreesUp(t *testing.T) {
	useHashLimits(t, HashLimits{MaxConcurrent: 1, MaxWait: 80 * time.Millisecond})
	kdf := newBlockingKDF()
	defer stubKDF(kdf.fn)()

	done := make(chan error, 1)
	go func() {
		_, err := HashPasswordContext(context.Background(), "pw12345678")
		done <- err
	}()
	kdf.waitEntered(t, 1)

	start := time.Now()
	hash, err := HashPasswordContext(context.Background(), "pw12345678")
	waited := time.Since(start)
	require.ErrorIs(t, err, ErrBusy)
	assert.Empty(t, hash)
	assert.GreaterOrEqual(t, waited, 80*time.Millisecond, "caller waits for the configured time")
	assert.Less(t, waited, 3*time.Second, "caller does not wait much longer than configured")
	assert.EqualValues(t, 1, kdf.calls.Load(), "the rejected caller never reached the KDF")

	// The verify path shares the same gate.
	stored := encodeTestHash(19, "m=65536,t=3,p=4", make([]byte, 16), make([]byte, 32))
	ok, err := VerifyPasswordContext(context.Background(), stored, "pw12345678")
	require.ErrorIs(t, err, ErrBusy)
	assert.False(t, ok)
	assert.EqualValues(t, 1, kdf.calls.Load())

	// Once the slot is released the next caller gets through.
	close(kdf.release)
	require.NoError(t, <-done)
	_, err = HashPasswordContext(context.Background(), "pw12345678")
	require.NoError(t, err)
}

func TestHashLimiterTakesAFreeSlotHoweverShortTheWait(t *testing.T) {
	// The wait only matters when every slot is taken. A wait of a nanosecond
	// (set to fail fast) has run out by the time the limiter looks at it;
	// with a free slot that must still not turn into ErrBusy. The stubbed
	// timer has always fired already, which is that situation every time.
	useHashLimits(t, HashLimits{MaxConcurrent: 1, MaxWait: time.Nanosecond})
	defer stubKDF(func(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
		return make([]byte, keyLen)
	})()
	realTimer := newWaitTimer
	newWaitTimer = func(time.Duration) (<-chan time.Time, func()) {
		fired := make(chan time.Time, 1)
		fired <- time.Now()
		return fired, func() {}
	}
	defer func() { newWaitTimer = realTimer }()

	for i := 0; i < 500; i++ {
		_, err := HashPasswordContext(context.Background(), "pw12345678")
		require.NoError(t, err, "call %d", i)
	}
}

func TestHashLimiterRefusesAContextThatIsAlreadyOver(t *testing.T) {
	// Every slot is free, and still a request whose context has ended gets
	// none: no KDF work for a client that has gone away.
	useHashLimits(t, HashLimits{MaxConcurrent: 4})
	var calls int
	defer stubKDF(func(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
		calls++
		return make([]byte, keyLen)
	})()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 50; i++ {
		_, err := HashPasswordContext(cancelled, "pw12345678")
		require.ErrorIs(t, err, ErrBusy)
		require.ErrorIs(t, err, context.Canceled)
		_, err = VerifyPasswordContext(cancelled, dummyHash, "pw12345678")
		require.ErrorIs(t, err, ErrBusy)
	}
	assert.Equal(t, 0, calls, "no KDF work for a cancelled request")

	// The same holds when the limit is switched off.
	useHashLimits(t, HashLimits{MaxConcurrent: -1})
	_, err := HashPasswordContext(cancelled, "pw12345678")
	require.ErrorIs(t, err, ErrBusy)
	assert.Equal(t, 0, calls)
}

func TestHashLimiterGetsTheSlotBackWhenTheKDFPanics(t *testing.T) {
	useHashLimits(t, HashLimits{MaxConcurrent: 1, MaxWait: 50 * time.Millisecond})
	restore := stubKDF(func(_, _ []byte, _, _ uint32, _ uint8, _ uint32) []byte {
		panic("kdf blew up")
	})
	require.Panics(t, func() { _, _ = HashPasswordContext(context.Background(), "pw12345678") })
	restore()

	// The only slot must be free again: a lost slot would make this ErrBusy.
	defer stubKDF(func(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
		return make([]byte, keyLen)
	})()
	_, err := HashPasswordContext(context.Background(), "pw12345678")
	require.NoError(t, err)
}

func TestHashLimiterStopsWaitingWhenContextEnds(t *testing.T) {
	useHashLimits(t, HashLimits{MaxConcurrent: 1, MaxWait: time.Minute})
	kdf := newBlockingKDF()
	defer stubKDF(kdf.fn)()
	defer close(kdf.release)

	go func() { _, _ = HashPasswordContext(context.Background(), "pw12345678") }()
	kdf.waitEntered(t, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := HashPasswordContext(ctx, "pw12345678")
	require.ErrorIs(t, err, ErrBusy)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestHashLimitsNegativeConcurrencyDisablesTheLimit(t *testing.T) {
	useHashLimits(t, HashLimits{MaxConcurrent: -1})
	kdf := newBlockingKDF()
	defer stubKDF(kdf.fn)()

	const callers = 12 // well above the default of 4
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := HashPasswordContext(context.Background(), "pw12345678")
			assert.NoError(t, err)
		}()
	}
	kdf.waitEntered(t, callers)
	assert.EqualValues(t, callers, kdf.inFlight.Load(), "all callers run at once when the limit is off")
	close(kdf.release)
	wg.Wait()
}

func TestHashLimitsNegativeWaitWaitsForTheContextOnly(t *testing.T) {
	useHashLimits(t, HashLimits{MaxConcurrent: 1, MaxWait: -1})
	kdf := newBlockingKDF()
	defer stubKDF(kdf.fn)()

	first := make(chan error, 1)
	go func() {
		_, err := HashPasswordContext(context.Background(), "pw12345678")
		first <- err
	}()
	kdf.waitEntered(t, 1)

	second := make(chan error, 1)
	go func() {
		_, err := HashPasswordContext(context.Background(), "pw12345678")
		second <- err
	}()
	select {
	case err := <-second:
		t.Fatalf("second caller returned while the slot was taken: %v", err)
	case <-time.After(300 * time.Millisecond):
		// still waiting, as configured
	}
	close(kdf.release)
	require.NoError(t, <-first)
	require.NoError(t, <-second)
}

func TestPlainHashAndVerifyGoThroughTheSameGate(t *testing.T) {
	// HashPassword and VerifyPassword (no context) are what existing callers
	// use; they must not bypass the limiter.
	useHashLimits(t, HashLimits{MaxConcurrent: 1, MaxWait: 50 * time.Millisecond})
	kdf := newBlockingKDF()
	defer stubKDF(kdf.fn)()
	defer close(kdf.release)

	go func() { _, _ = HashPassword("pw12345678") }()
	kdf.waitEntered(t, 1)

	_, err := HashPassword("pw12345678")
	require.ErrorIs(t, err, ErrBusy)
	stored := encodeTestHash(19, "m=65536,t=3,p=4", make([]byte, 16), make([]byte, 32))
	_, err = VerifyPassword(stored, "pw12345678")
	require.ErrorIs(t, err, ErrBusy)
}

func TestDummyHashUsesTheCurrentParameters(t *testing.T) {
	p, err := parseHash(dummyHash)
	require.NoError(t, err, "dummy hash must pass the parser")
	assert.EqualValues(t, argonMemoryKB, p.memoryKB)
	assert.EqualValues(t, argonIterations, p.iterations)
	assert.EqualValues(t, argonParallel, p.parallelism)
	assert.Len(t, p.salt, argonSaltBytes)
	assert.Len(t, p.key, argonKeyBytes)
}

func TestDummyVerifyDoesTheSameWorkAsARealVerify(t *testing.T) {
	type call struct {
		time, memory uint32
		threads      uint8
		keyLen       uint32
		password     string
	}
	var calls []call
	defer stubKDF(func(password, _ []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
		calls = append(calls, call{time, memory, threads, keyLen, string(password)})
		return make([]byte, keyLen)
	})()

	require.NoError(t, DummyVerify(context.Background(), "attacker supplied"))
	require.Len(t, calls, 1, "exactly one KDF run")
	assert.Equal(t, call{
		time: argonIterations, memory: argonMemoryKB, threads: argonParallel,
		keyLen: argonKeyBytes, password: "attacker supplied",
	}, calls[0])
}

func TestDummyVerifyIsSubjectToTheLimiter(t *testing.T) {
	useHashLimits(t, HashLimits{MaxConcurrent: 1, MaxWait: 50 * time.Millisecond})
	kdf := newBlockingKDF()
	defer stubKDF(kdf.fn)()
	defer close(kdf.release)

	go func() { _, _ = HashPasswordContext(context.Background(), "pw12345678") }()
	kdf.waitEntered(t, 1)

	require.ErrorIs(t, DummyVerify(context.Background(), "pw12345678"), ErrBusy)
}

func TestDummyVerifyWithTheRealKDF(t *testing.T) {
	// End to end, no stub: the dummy hash is well-formed for the real library
	// and no ordinary password matches it.
	require.NoError(t, DummyVerify(context.Background(), "correct horse battery staple"))
	ok, err := VerifyPassword(dummyHash, "")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestKDFHookRunsInsideTheSlotWithThePassword(t *testing.T) {
	useHashLimits(t, HashLimits{MaxConcurrent: 1, MaxWait: 50 * time.Millisecond})
	defer stubKDF(func(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
		return make([]byte, keyLen)
	})()

	entered := make(chan string, 1)
	release := make(chan struct{})
	restore := SetKDFHookForTesting(func(password string) {
		entered <- password
		<-release
	})
	done := make(chan error, 1)
	go func() {
		_, err := HashPasswordContext(context.Background(), "held-password")
		done <- err
	}()
	select {
	case pw := <-entered:
		assert.Equal(t, "held-password", pw)
	case <-time.After(5 * time.Second):
		t.Fatal("the hook was not called")
	}

	// The hook holds the only slot.
	_, err := HashPasswordContext(context.Background(), "other")
	require.ErrorIs(t, err, ErrBusy)
	close(release)
	require.NoError(t, <-done)

	// After restore nothing is called any more.
	restore()
	_, err = HashPasswordContext(context.Background(), "after-restore")
	require.NoError(t, err)
	assert.Empty(t, entered)
}

func TestKDFHookPanicGivesTheSlotBack(t *testing.T) {
	useHashLimits(t, HashLimits{MaxConcurrent: 1, MaxWait: 50 * time.Millisecond})
	defer stubKDF(func(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
		return make([]byte, keyLen)
	})()
	restore := SetKDFHookForTesting(func(string) { panic("hook blew up") })
	require.Panics(t, func() { _, _ = HashPasswordContext(context.Background(), "pw12345678") })
	restore()
	_, err := HashPasswordContext(context.Background(), "pw12345678")
	require.NoError(t, err, "a lost slot would make this ErrBusy")
}

// A nil hook clears the hook: hashes run without one, and the restore
// function brings back the hook that was installed before.
func TestKDFHookNilClearsTheHook(t *testing.T) {
	defer stubKDF(func(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
		return make([]byte, keyLen)
	})()
	var calls atomic.Int32
	restoreOuter := SetKDFHookForTesting(func(string) { calls.Add(1) })
	defer restoreOuter()

	restore := SetKDFHookForTesting(nil)
	require.NotPanics(t, func() {
		stored, err := HashPasswordContext(context.Background(), "pw12345678")
		require.NoError(t, err)
		ok, err := VerifyPasswordContext(context.Background(), stored, "pw12345678")
		require.NoError(t, err)
		assert.True(t, ok)
	}, "a nil hook must not be called")
	assert.Zero(t, calls.Load(), "no hook runs")

	restore()
	_, err := HashPasswordContext(context.Background(), "pw12345678")
	require.NoError(t, err)
	assert.EqualValues(t, 1, calls.Load(), "the earlier hook is back")
}
