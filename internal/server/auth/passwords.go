package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// Parameters HashPassword writes into every new hash.
const (
	argonMemoryKB   = 64 * 1024
	argonIterations = 3
	argonParallel   = 4
	argonSaltBytes  = 16
	argonKeyBytes   = 32
)

// Bounds the parser accepts in a stored hash. A hash outside them is
// rejected before the KDF runs: argon2 panics on t=0 or p=0, and m is the
// amount of memory the process allocates for one verification.
const (
	minHashMemoryKB    = 8 // argon2 needs 8 KiB per lane, so the minimum is 8*p
	maxHashMemoryKB    = 256 * 1024
	minHashIterations  = 1
	maxHashIterations  = 16
	minHashParallelism = 1
	maxHashParallelism = 16
	minHashSaltBytes   = 8
	maxHashSaltBytes   = 64
	minHashKeyBytes    = 16
	maxHashKeyBytes    = 64
)

// Defaults of the process-wide limit on password hash operations.
const (
	DefaultHashConcurrency = 4
	DefaultHashWait        = 5 * time.Second
)

var (
	// ErrBusy is returned by the hash and verify functions when no slot for
	// the operation became free in time. It says nothing about the password;
	// callers should answer with "try again later" (HTTP 429 or 503).
	ErrBusy = errors.New("auth: password hashing is at capacity")

	// ErrMalformedHash is returned by the verify functions when the stored
	// hash is not an argon2id hash this package accepts: wrong format, wrong
	// version, or parameters outside the accepted bounds.
	ErrMalformedHash = errors.New("auth: malformed argon2id hash")
)

// HashLimits bounds the argon2id work the whole process does at one time.
// One hash costs 64 MiB and four threads, so without a bound a burst of
// signups or logins exhausts the machine.
//
// Convention for both fields: zero selects the default, a negative value
// switches the bound off.
type HashLimits struct {
	// MaxConcurrent is the number of hash and verify operations that may run
	// at the same time. Zero selects DefaultHashConcurrency (4); a negative
	// value removes the limit.
	MaxConcurrent int
	// MaxWait is how long a caller waits for a free slot before it gets
	// ErrBusy. Zero selects DefaultHashWait (5 s); with a negative value only
	// the caller's context ends the wait.
	MaxWait time.Duration
}

// hashGate is one installed set of limits. slots is nil when the
// concurrency limit is off; wait is negative when the wait is unbounded.
type hashGate struct {
	slots chan struct{}
	wait  time.Duration
}

// gate holds the limits in force. It is set at package init, so the limit
// applies even when nobody calls SetHashLimits.
var gate atomic.Pointer[hashGate]

func init() { SetHashLimits(HashLimits{}) }

// SetHashLimits installs the process-wide limits for HashPassword,
// VerifyPassword, their Context variants and DummyVerify. It is meant to be
// called once at start-up; operations already running finish under the
// limits they started with.
func SetHashLimits(l HashLimits) {
	g := &hashGate{wait: l.MaxWait}
	if l.MaxWait == 0 {
		g.wait = DefaultHashWait
	}
	n := l.MaxConcurrent
	if n == 0 {
		n = DefaultHashConcurrency
	}
	if n > 0 {
		g.slots = make(chan struct{}, n)
	}
	gate.Store(g)
}

// acquire takes a slot and returns the function that gives it back. The
// error wraps ErrBusy, and the context's error too when the context ended
// the wait.
func (g *hashGate) acquire(ctx context.Context) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBusy, err)
	}
	if g.slots == nil {
		return func() {}, nil
	}
	release = func() { <-g.slots }

	// A free slot is taken at once. Without this, a wait that has already
	// run out when the select below starts (a wait of a nanosecond, set to
	// fail fast) could win over a free slot.
	select {
	case g.slots <- struct{}{}:
		return release, nil
	default:
	}

	var expired <-chan time.Time
	if g.wait >= 0 {
		var stop func()
		expired, stop = newWaitTimer(g.wait)
		defer stop()
	}
	select {
	case g.slots <- struct{}{}:
		return release, nil
	case <-expired:
		return nil, ErrBusy
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrBusy, ctx.Err())
	}
}

// newWaitTimer starts the clock for the wait for a slot. It is a variable so
// tests can hand in a timer that has already fired.
var newWaitTimer = func(d time.Duration) (expired <-chan time.Time, stop func()) {
	t := time.NewTimer(d)
	return t.C, func() { t.Stop() }
}

// argonIDKey is the KDF. It is a variable so tests can observe and block it.
var argonIDKey = argon2.IDKey

// kdfHook is the hook SetKDFHookForTesting installs; nil when none is.
var kdfHook atomic.Pointer[func(password string)]

// SetKDFHookForTesting installs hook, which every hash and verify operation
// (HashPassword, VerifyPassword, their Context variants and DummyVerify)
// then calls with the password while it holds its slot of the process-wide
// limit, just before the key derivation runs. It returns the function that
// removes the hook again. A panic in the hook leaves the operation like a
// panic in the KDF would: the slot is given back.
//
// It exists for tests in other packages that need password-hash work to
// stay in flight for a while, for example to fill the limit. Production code
// never calls it. One hook is installed at a time; tests that use it must
// not run in parallel with other users of the hash functions. A nil hook
// removes the one installed (restore puts it back).
func SetKDFHookForTesting(hook func(password string)) (restore func()) {
	var p *func(string)
	if hook != nil {
		p = &hook
	}
	prev := kdfHook.Swap(p)
	return func() { kdfHook.Store(prev) }
}

// UseCheapKDFForTesting makes every hash and verify operation derive its key
// at the lowest argon2id cost (one pass over 8 KiB per lane) instead of the
// cost the hash names. Hash strings keep their form and their parameters,
// so a hash made this way verifies only while the cheap KDF is in use, and
// the real hashes (dummyHash among them) match no password. Slots, waits,
// errors and the hook of SetKDFHookForTesting work as before. It returns the
// function that puts the real KDF back.
//
// It exists for test binaries that hash hundreds of times and assert what
// the callers of the hash functions do, not what a hash costs: at the real
// cost (64 MiB, three passes) they spend minutes in the KDF on a small
// machine. Production code never calls it. Call it before any hash work
// starts and restore after all of it has ended, in TestMain for example: it
// is not safe while hash operations run.
func UseCheapKDFForTesting() (restore func()) {
	prev := argonIDKey
	argonIDKey = func(password, salt []byte, _, _ uint32, threads uint8, keyLen uint32) []byte {
		return argon2.IDKey(password, salt, 1, 8*uint32(threads), threads, keyLen)
	}
	return func() { argonIDKey = prev }
}

// deriveKey runs the KDF inside the process-wide limit.
func deriveKey(ctx context.Context, password string, salt []byte, iterations, memoryKB uint32, parallelism uint8, keyLen uint32) ([]byte, error) {
	release, err := gate.Load().acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if hook := kdfHook.Load(); hook != nil {
		(*hook)(password)
	}
	return argonIDKey([]byte(password), salt, iterations, memoryKB, parallelism, keyLen), nil
}

// HashPassword returns a self-describing argon2id hash string of the form
// $argon2id$v=<version>$m=<memKB>,t=<iter>,p=<par>$<salt-b64>$<key-b64>.
//
// It is HashPasswordContext without a context: the wait for a slot is
// bounded by HashLimits.MaxWait only. Returns ErrBusy when no slot is free.
func HashPassword(password string) (string, error) {
	return HashPasswordContext(context.Background(), password)
}

// HashPasswordContext is HashPassword with a context that can end the wait
// for a hashing slot early. The hash computation itself is not interrupted.
// Returns an error wrapping ErrBusy when no slot became free in time.
func HashPasswordContext(ctx context.Context, password string) (string, error) {
	salt := make([]byte, argonSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	key, err := deriveKey(ctx, password, salt, argonIterations, argonMemoryKB, argonParallel, argonKeyBytes)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemoryKB, argonIterations, argonParallel,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether password matches the stored argon2id hash.
//
// It is VerifyPasswordContext without a context. Returns ErrMalformedHash
// for a stored hash the parser rejects and ErrBusy when no slot is free.
func VerifyPassword(stored, password string) (bool, error) {
	return VerifyPasswordContext(context.Background(), stored, password)
}

// VerifyPasswordContext is VerifyPassword with a context that can end the
// wait for a hashing slot early.
func VerifyPasswordContext(ctx context.Context, stored, password string) (bool, error) {
	p, err := parseHash(stored)
	if err != nil {
		return false, err
	}
	got, err := deriveKey(ctx, password, p.salt, p.iterations, p.memoryKB, p.parallelism, uint32(len(p.key)))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, p.key) == 1, nil
}

// dummyHash is a fixed hash with the parameters HashPassword uses. It was
// made from a random password that was thrown away, so no login matches it.
// A test pins its parameters to the constants above: when they change, this
// value has to be regenerated.
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$woMQc9mYFGVAEjakAiHt1g$1R18ep4e3IgZ3NBTeQ+y/NY1VuBty/AofQvQcT65+XU"

// DummyVerify does the work of one VerifyPassword call against a fixed hash
// and discards the result. A login for an email address without an account
// calls it so that it takes as long, and counts against the same limit, as
// a login for an existing account. The only error is ErrBusy.
func DummyVerify(ctx context.Context, password string) error {
	_, err := VerifyPasswordContext(ctx, dummyHash, password)
	return err
}

// hashParams is a stored hash taken apart, with every value inside the
// accepted bounds.
type hashParams struct {
	memoryKB    uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	key         []byte
}

// parseHash takes a stored hash apart and checks version and bounds. Every
// error wraps ErrMalformedHash. The hash value itself never appears in the
// error text.
func parseHash(stored string) (hashParams, error) {
	var p hashParams
	// A well-formed hash has six parts. Asking for at most seven keeps the
	// split small however long the stored string is.
	parts := strings.SplitN(stored, "$", 7)
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, fmt.Errorf("%w: not in $argon2id$v=..$m=..,t=..,p=..$salt$key form", ErrMalformedHash)
	}

	version, ok := parseField(parts[2], "v=")
	if !ok || version != argon2.Version {
		return p, fmt.Errorf("%w: unsupported version", ErrMalformedHash)
	}

	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return p, fmt.Errorf("%w: expected m, t and p", ErrMalformedHash)
	}
	mem, okM := parseField(params[0], "m=")
	iter, okT := parseField(params[1], "t=")
	par, okP := parseField(params[2], "p=")
	if !okM || !okT || !okP {
		return p, fmt.Errorf("%w: expected m, t and p", ErrMalformedHash)
	}
	if iter < minHashIterations || iter > maxHashIterations {
		return p, fmt.Errorf("%w: t outside %d..%d", ErrMalformedHash, minHashIterations, maxHashIterations)
	}
	if par < minHashParallelism || par > maxHashParallelism {
		return p, fmt.Errorf("%w: p outside %d..%d", ErrMalformedHash, minHashParallelism, maxHashParallelism)
	}
	if mem < minHashMemoryKB*par || mem > maxHashMemoryKB {
		return p, fmt.Errorf("%w: m outside %d..%d KiB for p=%d", ErrMalformedHash, minHashMemoryKB*par, maxHashMemoryKB, par)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < minHashSaltBytes || len(salt) > maxHashSaltBytes {
		return p, fmt.Errorf("%w: salt is not %d..%d bytes of base64", ErrMalformedHash, minHashSaltBytes, maxHashSaltBytes)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < minHashKeyBytes || len(key) > maxHashKeyBytes {
		return p, fmt.Errorf("%w: key is not %d..%d bytes of base64", ErrMalformedHash, minHashKeyBytes, maxHashKeyBytes)
	}

	return hashParams{
		memoryKB:    uint32(mem),
		iterations:  uint32(iter),
		parallelism: uint8(par),
		salt:        salt,
		key:         key,
	}, nil
}

// parseField reads "<prefix><decimal digits>" and nothing else. ParseUint
// in base 10 takes digits only: no sign, no spaces, no trailer, and no value
// beyond 32 bits.
func parseField(s, prefix string) (uint64, bool) {
	digits, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil {
		return 0, false
	}
	return n, true
}
