package reservations

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func TestNormalizeSubdomainAccepts(t *testing.T) {
	cases := map[string]string{
		"myapp":                             "myapp",
		"MyApp":                             "myapp",
		"  myapp\t":                         "myapp",
		" MY-App-2 ":                        "my-app-2",
		"abc":                               "abc",
		"a-b":                               "a-b",
		"123":                               "123",
		"0a0":                               "0a0",
		"xn--bcher-kva":                     "xn--bcher-kva",
		strings.Repeat("a", 63):             strings.Repeat("a", 63),
		"a" + strings.Repeat("-", 61) + "b": "a" + strings.Repeat("-", 61) + "b",
	}
	for in, want := range cases {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			got, err := NormalizeSubdomain(in)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestNormalizeSubdomainRejectsInvalid(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"a",
		"ab",
		"-abc",
		"abc-",
		"-",
		"---",
		"a_b",
		"a.b",
		"a b",
		"a/b",
		"../../users/7/promote?x=",
		"abc\x00",
		"ab\ncd",
		"ab\r\ncd",
		"<script>",
		"müller",
		"\u212Aube", // KELVIN SIGN lower-cases to an ASCII k
		"ａｂｃ",       // full-width letters
		strings.Repeat("a", 64),
		strings.Repeat("a", 5000),
	}
	for _, in := range cases {
		t.Run(fmt.Sprintf("%q", truncateForName(in)), func(t *testing.T) {
			got, err := NormalizeSubdomain(in)
			require.ErrorIs(t, err, ErrInvalidSubdomain)
			assert.Empty(t, got)
		})
	}
}

func truncateForName(s string) string {
	if len(s) > 40 {
		return s[:40]
	}
	return s
}

func TestNormalizeSubdomainRejectsSystemReserved(t *testing.T) {
	required := []string{
		"www", "api", "app", "admin", "mail", "dashboard", "status",
		"login", "auth", "signup", "support", "smtp", "imap", "ftp",
		"ns1", "ns2", "static", "cdn", "metrics", "tunnel",
	}
	for _, name := range required {
		t.Run(name, func(t *testing.T) {
			for _, in := range []string{name, strings.ToUpper(name), "  " + name + " "} {
				got, err := NormalizeSubdomain(in)
				require.ErrorIs(t, err, ErrSystemReserved, "input %q", in)
				assert.Empty(t, got)
			}
			assert.True(t, IsSystemReserved(name))
		})
	}
}

// Every entry of the list must itself be a well-formed name, otherwise it
// could never match what NormalizeSubdomain compares against.
func TestSystemReservedNamesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range SystemReservedNames {
		assert.True(t, subdomainRE.MatchString(name), "%q is not a well-formed subdomain", name)
		assert.False(t, seen[name], "%q listed twice", name)
		seen[name] = true
	}
}

func newUser(t *testing.T, svc *users.Service, email string) int64 {
	t.Helper()
	u, err := svc.Create(context.Background(), email, "pw12345678")
	require.NoError(t, err)
	return u.ID
}

func TestReserveStoresNormalizedName(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	uid := newUser(t, users.NewService(pool), "norm@example.com")
	svc := NewService(pool)

	require.NoError(t, svc.Reserve(ctx, "  MyApp ", uid))

	owner, reserved, err := svc.Owner(ctx, "myapp")
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, uid, owner)

	rows, err := svc.ListByUser(ctx, uid)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "myapp", rows[0].Subdomain)
}

func TestReserveTreatsCaseVariantsAsTheSameName(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	userSvc := users.NewService(pool)
	u1 := newUser(t, userSvc, "case1@example.com")
	u2 := newUser(t, userSvc, "case2@example.com")
	svc := NewService(pool)

	require.NoError(t, svc.Reserve(ctx, "MyApp", u1))
	require.ErrorIs(t, svc.Reserve(ctx, "myapp", u2), ErrAlreadyReserved)
	require.ErrorIs(t, svc.GrantSubdomain(ctx, "MYAPP", u2), ErrAlreadyReserved)
}

func TestReserveAndGrantRejectBadNames(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	uid := newUser(t, users.NewService(pool), "bad@example.com")
	svc := NewService(pool)

	invalid := []string{"", "ab", "a_b", "a.b", "../../users/7/promote?x=", strings.Repeat("a", 64)}
	for _, name := range invalid {
		assert.ErrorIs(t, svc.Reserve(ctx, name, uid), ErrInvalidSubdomain, "Reserve(%q)", name)
		assert.ErrorIs(t, svc.GrantSubdomain(ctx, name, uid), ErrInvalidSubdomain, "GrantSubdomain(%q)", name)
	}
	for _, name := range []string{"admin", "WWW", "login", "tunnel"} {
		assert.ErrorIs(t, svc.Reserve(ctx, name, uid), ErrSystemReserved, "Reserve(%q)", name)
		assert.ErrorIs(t, svc.GrantSubdomain(ctx, name, uid), ErrSystemReserved, "GrantSubdomain(%q)", name)
	}

	n, err := svc.CountSubdomains(ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "a rejected name must not be stored")
}

func TestGrantSubdomainStoresNormalizedName(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	uid := newUser(t, users.NewService(pool), "grantnorm@example.com")
	svc := NewService(pool)

	require.NoError(t, svc.GrantSubdomain(ctx, " Granted-App ", uid))

	owner, reserved, err := svc.Owner(ctx, "granted-app")
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, uid, owner)
}

func reserveN(t *testing.T, svc *Service, uid int64, prefix string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		require.NoError(t, svc.Reserve(context.Background(), fmt.Sprintf("%s-%d", prefix, i), uid))
	}
}

func TestReserveEnforcesDefaultPerUserLimit(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	userSvc := users.NewService(pool)
	u1 := newUser(t, userSvc, "limit1@example.com")
	u2 := newUser(t, userSvc, "limit2@example.com")
	svc := NewService(pool)

	// 10 is the default: nine and ten go through,
	// the eleventh does not.
	reserveN(t, svc, u1, "one", 10)

	require.ErrorIs(t, svc.Reserve(ctx, "one-too-many", u1), ErrReservationLimit)
	_, reserved, err := svc.Owner(ctx, "one-too-many")
	require.NoError(t, err)
	assert.False(t, reserved, "the rejected reservation must not exist")

	// The limit is per user.
	require.NoError(t, svc.Reserve(ctx, "two-first", u2))

	// Releasing one makes room again.
	require.NoError(t, svc.Release(ctx, "one-0", u1))
	require.NoError(t, svc.Reserve(ctx, "one-again", u1))
	require.ErrorIs(t, svc.Reserve(ctx, "one-and-again", u1), ErrReservationLimit)
}

func TestReserveLimitIsConfigurable(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	uid := newUser(t, users.NewService(pool), "cfg@example.com")

	svc := NewServiceWithOptions(pool, Options{MaxSubdomainsPerUser: 2})
	reserveN(t, svc, uid, "cfg", 2)
	require.ErrorIs(t, svc.Reserve(ctx, "cfg-third", uid), ErrReservationLimit)

	// A negative value disables the limit.
	unlimited := NewServiceWithOptions(pool, Options{MaxSubdomainsPerUser: -1})
	reserveN(t, unlimited, uid, "many", 12)
	// Names are normalised and validated on this path too.
	require.NoError(t, unlimited.Reserve(ctx, " Mixed-Case ", uid))
	owner, reserved, err := unlimited.Owner(ctx, "mixed-case")
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, uid, owner)
	require.ErrorIs(t, unlimited.Reserve(ctx, "a_b", uid), ErrInvalidSubdomain)

	// Zero means "default", not "none".
	def := NewServiceWithOptions(pool, Options{})
	require.ErrorIs(t, def.Reserve(ctx, "over-default", uid), ErrReservationLimit)
}

func TestGrantSubdomainIsNotLimitedButCounts(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	uid := newUser(t, users.NewService(pool), "grantlimit@example.com")
	svc := NewServiceWithOptions(pool, Options{MaxSubdomainsPerUser: 1})

	require.NoError(t, svc.Reserve(ctx, "own-one", uid))
	// An admin grant goes through although the user is at the limit ...
	require.NoError(t, svc.GrantSubdomain(ctx, "granted-one", uid))
	require.NoError(t, svc.GrantSubdomain(ctx, "granted-two", uid))
	// ... and the user still cannot add more on their own.
	require.ErrorIs(t, svc.Reserve(ctx, "own-two", uid), ErrReservationLimit)
}

// Concurrent requests must not slip past the limit between the count and the
// insert.
func TestReserveLimitHoldsUnderConcurrency(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	uid := newUser(t, users.NewService(pool), "race@example.com")
	const limit = 3
	svc := NewServiceWithOptions(pool, Options{MaxSubdomainsPerUser: limit})

	const attempts = 16
	errs := make([]error, attempts)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = svc.Reserve(ctx, fmt.Sprintf("race-%d", i), uid)
		}(i)
	}
	close(start)
	wg.Wait()

	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
			continue
		}
		require.ErrorIs(t, err, ErrReservationLimit)
	}
	assert.Equal(t, limit, ok)

	n, err := svc.CountSubdomainsByUser(ctx, uid)
	require.NoError(t, err)
	assert.EqualValues(t, limit, n)
}

func TestPortMethodsRejectOutOfRangePorts(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	uid := newUser(t, users.NewService(pool), "ports@example.com")
	svc := NewService(pool)

	// Port 80 is reserved; 1<<32+80 has the same low 32 bits. The number is
	// built as an int64 and only used where int can hold it, so that the test
	// also compiles and passes on 32-bit targets.
	require.NoError(t, svc.GrantTCPPort(ctx, 80, uid))
	require.NoError(t, svc.GrantUDPPort(ctx, 80, uid))
	ports := []int{0, -1, -80, 65536, 70000}
	if wraps := int64(1)<<32 + 80; int64(int(wraps)) == wraps {
		ports = append(ports, int(wraps))
	}

	for _, port := range ports {
		assert.ErrorIs(t, svc.ReserveTCPPort(ctx, port, uid), ErrInvalidPort, "ReserveTCPPort(%d)", port)
		assert.ErrorIs(t, svc.ReserveUDPPort(ctx, port, uid), ErrInvalidPort, "ReserveUDPPort(%d)", port)
		assert.ErrorIs(t, svc.GrantTCPPort(ctx, port, uid), ErrInvalidPort, "GrantTCPPort(%d)", port)
		assert.ErrorIs(t, svc.GrantUDPPort(ctx, port, uid), ErrInvalidPort, "GrantUDPPort(%d)", port)
		assert.ErrorIs(t, svc.ReleaseTCPPort(ctx, port, uid), ErrInvalidPort, "ReleaseTCPPort(%d)", port)
		assert.ErrorIs(t, svc.ReleaseUDPPort(ctx, port, uid), ErrInvalidPort, "ReleaseUDPPort(%d)", port)
		assert.ErrorIs(t, svc.RevokeTCPPort(ctx, port), ErrInvalidPort, "RevokeTCPPort(%d)", port)
		assert.ErrorIs(t, svc.RevokeUDPPort(ctx, port), ErrInvalidPort, "RevokeUDPPort(%d)", port)

		owner, reserved, err := svc.OwnerTCPPort(ctx, port)
		assert.ErrorIs(t, err, ErrInvalidPort, "OwnerTCPPort(%d)", port)
		assert.False(t, reserved)
		assert.Zero(t, owner)
		owner, reserved, err = svc.OwnerUDPPort(ctx, port)
		assert.ErrorIs(t, err, ErrInvalidPort, "OwnerUDPPort(%d)", port)
		assert.False(t, reserved)
		assert.Zero(t, owner)
	}

	// The reservation of port 80 survived every out-of-range call above.
	owner, reserved, err := svc.OwnerTCPPort(ctx, 80)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, uid, owner)
	owner, reserved, err = svc.OwnerUDPPort(ctx, 80)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, uid, owner)
}

func TestPortMethodsAcceptRangeBoundaries(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()
	uid := newUser(t, users.NewService(pool), "bounds@example.com")
	svc := NewService(pool)

	for _, port := range []int{1, 65535} {
		require.NoError(t, svc.ReserveTCPPort(ctx, port, uid))
		require.NoError(t, svc.ReserveUDPPort(ctx, port, uid))
		owner, reserved, err := svc.OwnerTCPPort(ctx, port)
		require.NoError(t, err)
		assert.True(t, reserved)
		assert.Equal(t, uid, owner)
		require.NoError(t, svc.ReleaseTCPPort(ctx, port, uid))
		require.NoError(t, svc.RevokeUDPPort(ctx, port))
	}
}
