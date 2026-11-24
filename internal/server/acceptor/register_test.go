package acceptor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeudp"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// ---- subdomain names ----

func TestRegisterHTTPRejectsInvalidNames(t *testing.T) {
	logger, logs := captureLogger()
	reg := registry.New()
	opts := staticOpts()
	opts.Registry = reg
	opts.Logger = logger
	opts.ControlBurst = -1
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, staticToken)

	names := []string{
		"ab", "a_b", "a.b", "-abc", "abc-", "a b", "a/b", "../../users/7/promote?x=",
		"abc\x00", "ab\ncd", "<script>", "müller", "\u212Aube", strings.Repeat("a", 64),
	}
	for _, name := range names {
		ack := c.registerHTTP(name)
		assert.Equal(t, "invalid subdomain", ack.Error, "name %q", name)
		assert.Empty(t, ack.Subdomain)
		assert.Empty(t, ack.PublicURL)
	}
	assert.Empty(t, reg.Snapshot(), "nothing may be registered")
	// A refused name is text from the client; it stays out of the log.
	assert.NotContains(t, logs.String(), "promote")
	assert.NotContains(t, logs.String(), "script")

	// The session is intact and takes a valid name afterwards.
	ack := c.registerHTTP("valid-name")
	require.Empty(t, ack.Error)
	assert.Equal(t, "valid-name", ack.Subdomain)
}

func TestRegisterHTTPRejectsSystemReservedNamesInStaticMode(t *testing.T) {
	reg := registry.New()
	opts := staticOpts()
	opts.Registry = reg
	opts.ControlBurst = -1
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, staticToken)

	for _, name := range []string{"www", "api", "app", "admin", "mail", "dashboard", "status", "login", "tunnel", "ADMIN", " App "} {
		ack := c.registerHTTP(name)
		assert.Equal(t, "subdomain reserved", ack.Error, "name %q", name)
		assert.Empty(t, ack.PublicURL)
	}
	assert.Empty(t, reg.Snapshot())
}

func TestRegisterHTTPRejectsSystemReservedNamesInDatabaseMode(t *testing.T) {
	fx := newDBFixture(t)
	_, raw := fx.user(t, "sys@example.com")
	reg := registry.New()
	opts := fx.dbOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, raw)

	for _, name := range []string{"admin", "login", "WWW"} {
		assert.Equal(t, "subdomain reserved", c.registerHTTP(name).Error, "name %q", name)
	}
	assert.Equal(t, "invalid subdomain", c.registerHTTP("a_b").Error)
	assert.Empty(t, reg.Snapshot())
}

func TestRegisterHTTPNormalisesTheName(t *testing.T) {
	reg := registry.New()
	opts := staticOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)
	c, hello := login(t, addr, staticToken)

	ack := c.registerHTTP("  My-App ")
	require.Empty(t, ack.Error)
	assert.Equal(t, "my-app", ack.Subdomain)
	assert.Equal(t, "https://my-app.tunnel.localhost", ack.PublicURL)

	s, ok := reg.LookupHTTP("my-app")
	require.True(t, ok)
	assert.Equal(t, hello.SessionID, s.ID())
	_, ok = reg.LookupHTTP("My-App")
	assert.False(t, ok)
}

// A different spelling of a name somebody else reserved is that name.
func TestRegisterHTTPCaseVariantOfForeignReservationIsRejected(t *testing.T) {
	fx := newDBFixture(t)
	ctx := context.Background()
	owner, ownerRaw := fx.user(t, "owner@example.com")
	_, otherRaw := fx.user(t, "other@example.com")
	require.NoError(t, fx.res.Reserve(ctx, "shiny", owner))
	reg := registry.New()
	opts := fx.dbOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)

	other, _ := login(t, addr, otherRaw)
	for _, name := range []string{"shiny", "Shiny", "SHINY", " shiny "} {
		assert.Equal(t, "subdomain reserved", other.registerHTTP(name).Error, "name %q", name)
	}
	_, ok := reg.LookupHTTP("shiny")
	assert.False(t, ok)

	// The owner gets it under any spelling.
	mine, _ := login(t, addr, ownerRaw)
	ack := mine.registerHTTP("Shiny")
	require.Empty(t, ack.Error)
	assert.Equal(t, "shiny", ack.Subdomain)
}

// The name check comes before the reservation lookup: a bad name never
// reaches the database.
func TestRegisterHTTPChecksTheNameBeforeTheReservationLookup(t *testing.T) {
	fx := newDBFixture(t)
	_, raw := fx.user(t, "order@example.com")
	lookup := &fakeLookup{answer: func(string, int) (int64, bool, error) { return 0, false, nil }}
	addr, _ := serve(t, fx.dbOpts(), func(a *Acceptor) { a.res = lookup })
	c, _ := login(t, addr, raw)

	assert.Equal(t, "invalid subdomain", c.registerHTTP("a_b").Error)
	assert.Equal(t, "subdomain reserved", c.registerHTTP("admin").Error)
	assert.Zero(t, lookup.count("http"), "no reservation lookup for a rejected name")

	require.Empty(t, c.registerHTTP("fine-name").Error)
	assert.Equal(t, 2, lookup.count("http"), "one lookup before and one after the registration")
}

// A random name is checked against the reservations like a requested one:
// once before and once after the registration.
func TestRegisterHTTPRandomNameIsCheckedAgainstReservations(t *testing.T) {
	fx := newDBFixture(t)
	_, raw := fx.user(t, "random@example.com")
	lookup := &fakeLookup{answer: func(string, int) (int64, bool, error) { return 0, false, nil }}
	addr, _ := serve(t, fx.dbOpts(), func(a *Acceptor) { a.res = lookup })
	c, _ := login(t, addr, raw)

	ack := c.registerHTTP("")
	require.Empty(t, ack.Error)
	assert.Len(t, ack.Subdomain, 6)
	assert.Equal(t, 2, lookup.count("http"))
}

// draws returns a random-name source that hands out names in order.
func draws(names ...string) func() (string, error) {
	var mu sync.Mutex
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if len(names) == 0 {
			return "", errors.New("no more names in the script")
		}
		n := names[0]
		names = names[1:]
		return n, nil
	}
}

// A drawn name that another user has reserved is not served: the server
// draws again. Before, the random holder served the reserved name and its
// owner got "subdomain taken" until the holder disconnected.
func TestRandomNameReservedForAnotherUserIsDrawnAgain(t *testing.T) {
	fx := newDBFixture(t)
	ctx := context.Background()
	owner, _ := fx.user(t, "owner@example.com")
	uid, raw := fx.user(t, "drawer@example.com")
	require.NoError(t, fx.res.Reserve(ctx, "taken1", owner))
	require.NoError(t, fx.res.Reserve(ctx, "mine22", uid))
	reg := registry.New()
	opts := fx.dbOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, func(a *Acceptor) { a.randomSubdomain = draws("taken1", "fresh2", "mine22") })

	c, _ := login(t, addr, raw)
	ack := c.registerHTTP("")
	require.Empty(t, ack.Error)
	assert.Equal(t, "fresh2", ack.Subdomain, "the reserved name is skipped")
	_, ok := reg.LookupHTTP("taken1")
	assert.False(t, ok)

	// A drawn name reserved for the drawing user is kept.
	c2, _ := login(t, addr, raw)
	ack = c2.registerHTTP("")
	require.Empty(t, ack.Error)
	assert.Equal(t, "mine22", ack.Subdomain)
}

// A reservation made between the check and the registration is noticed by
// the check after it: the name is given back and another one drawn.
func TestRandomNameReservedDuringRegistrationIsDrawnAgain(t *testing.T) {
	reserved := &nameLookup{owners: map[string]int64{}}
	reserved.afterCheck = func(name string, calls int) {
		if name == "racy11" && calls == 1 {
			reserved.set("racy11", 999) // reserved for somebody else right after the first check
		}
	}
	reg := registry.New()
	fx := newDBFixture(t)
	_, raw := fx.user(t, "race@example.com")
	opts := fx.dbOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, func(a *Acceptor) {
		a.res = reserved
		a.randomSubdomain = draws("racy11", "calm22")
	})
	c, _ := login(t, addr, raw)
	ack := c.registerHTTP("")
	require.Empty(t, ack.Error)
	assert.Equal(t, "calm22", ack.Subdomain)
	_, ok := reg.LookupHTTP("racy11")
	assert.False(t, ok, "the registration of the name that got reserved is rolled back")
}

// The draws are bounded; a lookup that fails refuses without drawing again.
func TestRandomNameDrawsAreBounded(t *testing.T) {
	logger, logs := captureLogger()
	everything := &fakeLookup{answer: func(string, int) (int64, bool, error) { return 999, true, nil }}
	reg := registry.New()
	opts := staticOpts()
	opts.Registry = reg
	opts.Logger = logger
	var drawn atomic.Int32
	addr, _ := serve(t, opts, func(a *Acceptor) {
		a.res = everything
		a.randomSubdomain = func() (string, error) {
			n := drawn.Add(1)
			return fmt.Sprintf("name%02d", n), nil
		}
	})
	c, _ := login(t, addr, staticToken)
	assert.Equal(t, "internal error", c.registerHTTP("").Error)
	assert.EqualValues(t, maxSubdomainDraws, drawn.Load())
	assert.Empty(t, reg.Snapshot())
	assert.Contains(t, logs.String(), "no unreserved subdomain drawn")

	failing := &fakeLookup{answer: func(string, int) (int64, bool, error) { return 0, false, errors.New("database went away") }}
	drawn.Store(0)
	addr2, _ := serve(t, opts, func(a *Acceptor) {
		a.res = failing
		a.randomSubdomain = func() (string, error) { drawn.Add(1); return "solo11", nil }
	})
	c2, _ := login(t, addr2, staticToken)
	assert.Equal(t, "internal error", c2.registerHTTP("").Error)
	assert.EqualValues(t, 1, drawn.Load(), "one draw only")
}

func TestRegisterHTTPFixedErrorTexts(t *testing.T) {
	reg := registry.New()
	opts := staticOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)

	first, _ := login(t, addr, staticToken)
	require.Empty(t, first.registerHTTP("contested").Error)
	assert.Equal(t, "session already has a subdomain", first.registerHTTP("another-one").Error)

	second, _ := login(t, addr, staticToken)
	assert.Equal(t, "subdomain taken", second.registerHTTP("contested").Error)
	assert.Equal(t, "subdomain taken", second.registerHTTP("Contested").Error)

	require.NoError(t, second.send("register_http", "not-an-object"))
	var ack struct{ Error string }
	second.mustRecv("register_http_ack", &ack)
	assert.Equal(t, "bad payload", ack.Error)
}

// ---- reservation lookups fail closed ----

func TestReservationLookupErrorDeniesAndStaysInternal(t *testing.T) {
	fx := newDBFixture(t)
	_, raw := fx.user(t, "failclosed@example.com")
	logger, logs := captureLogger()
	lookup := &fakeLookup{answer: func(string, int) (int64, bool, error) {
		return 0, false, errors.New("pq: SECRET-DSN-DETAIL connection refused")
	}}
	reg := registry.New()
	tcp, udp := &fakeEdge{}, &fakeEdge{}
	opts := fx.dbOpts()
	opts.Registry = reg
	opts.Logger = logger
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, func(a *Acceptor) { a.res = lookup })
	c, _ := login(t, addr, raw)

	assert.Equal(t, "internal error", c.registerHTTP("some-name").Error)
	assert.Equal(t, "internal error", c.registerTCP(20001).Error)
	assert.Equal(t, "internal error", c.registerUDP(30001).Error)

	assert.Empty(t, reg.Snapshot())
	_, ok := reg.LookupTCP(20001)
	assert.False(t, ok)
	_, ok = reg.LookupUDP(30001)
	assert.False(t, ok)
	assert.Empty(t, tcp.opened(), "no listener may be opened when the check cannot be made")
	assert.Empty(t, udp.opened())
	// The original error belongs in the server log, once for each lookup.
	assert.Equal(t, 3, strings.Count(logs.String(), "SECRET-DSN-DETAIL"), "log: %s", logs.String())
}

// A port drawn for "any" whose reservation cannot be looked up is refused
// with the internal error. It is not treated like a port that belongs to
// somebody else: there is no reason to draw eight times against a database
// that does not answer.
func TestDrawnPortWithFailingLookupIsRefusedWithoutRedrawing(t *testing.T) {
	lookup := &fakeLookup{answer: func(string, int) (int64, bool, error) {
		return 0, false, errors.New("database went away")
	}}
	reg := registry.New()
	tcp, udp := &fakeEdge{}, &fakeEdge{next: 500}
	opts := staticOpts()
	opts.Registry = reg
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, func(a *Acceptor) { a.res = lookup })
	c, _ := login(t, addr, staticToken)

	assert.Equal(t, "internal error", c.registerTCP(0).Error)
	assert.Equal(t, []int{0}, tcp.opened(), "one draw only")
	assert.Equal(t, []int{40000}, tcp.closed())
	_, ok := reg.LookupTCP(40000)
	assert.False(t, ok)

	assert.Equal(t, "internal error", c.registerUDP(0).Error)
	assert.Equal(t, []int{0}, udp.opened(), "one draw only")
	assert.Equal(t, []int{40500}, udp.closed())
	_, ok = reg.LookupUDP(40500)
	assert.False(t, ok)
}

// blockingLookup is a reservation lookup that does not answer until its
// context ends, like a query against a database that stalls.
type blockingLookup struct{ calls atomic.Int32 }

func (b *blockingLookup) wait(ctx context.Context) (int64, bool, error) {
	b.calls.Add(1)
	<-ctx.Done()
	return 0, false, ctx.Err()
}

func (b *blockingLookup) Owner(ctx context.Context, _ string) (int64, bool, error) {
	return b.wait(ctx)
}
func (b *blockingLookup) OwnerTCPPort(ctx context.Context, _ int) (int64, bool, error) {
	return b.wait(ctx)
}
func (b *blockingLookup) OwnerUDPPort(ctx context.Context, _ int) (int64, bool, error) {
	return b.wait(ctx)
}

// A reservation lookup is bounded by the verify timeout and refuses when it
// runs out. Before, it used the server's context: during a database stall
// the session's control loop hung, and a session killed meanwhile kept its
// port until the query returned.
func TestReservationLookupsHaveADeadline(t *testing.T) {
	const timeout = 300 * time.Millisecond
	lookup := &blockingLookup{}
	reg := registry.New()
	tcp, udp := &fakeEdge{}, &fakeEdge{}
	opts := staticOpts()
	opts.Registry = reg
	opts.VerifyTimeout = timeout
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, func(a *Acceptor) { a.res = lookup })
	c, _ := login(t, addr, staticToken)

	for name, register := range map[string]func() string{
		"named subdomain":  func() string { return c.registerHTTP("stalled-name").Error },
		"random subdomain": func() string { return c.registerHTTP("").Error },
		"tcp port":         func() string { return c.registerTCP(20001).Error },
		"udp port":         func() string { return c.registerUDP(30001).Error },
	} {
		start := time.Now()
		assert.Equal(t, "internal error", register(), name)
		took := time.Since(start)
		assert.GreaterOrEqual(t, took, timeout, name)
		assert.Less(t, took, timeout+5*time.Second, name)
	}
	assert.EqualValues(t, 4, lookup.calls.Load(), "one lookup each; a failed one is not repeated")
	assert.Empty(t, reg.Snapshot())
	assert.Empty(t, tcp.opened(), "no listener without an answer")
	c.requireOpen() // the control loop goes on
}

// A lookup that fails after the registration rolls the registration back.
func TestReservationLookupErrorAfterRegistrationRollsBack(t *testing.T) {
	fx := newDBFixture(t)
	uid, raw := fx.user(t, "rollback-err@example.com")
	lookup := &fakeLookup{answer: func(kind string, call int) (int64, bool, error) {
		if call == 1 {
			return uid, kind != "http", nil // the port is reserved for this user, the name is free
		}
		return 0, false, errors.New("database went away")
	}}
	reg := registry.New()
	tcp, udp := &fakeEdge{}, &fakeEdge{}
	opts := fx.dbOpts()
	opts.Registry = reg
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, func(a *Acceptor) { a.res = lookup })
	c, _ := login(t, addr, raw)

	assert.Equal(t, "internal error", c.registerHTTP("some-name").Error)
	assert.Equal(t, "internal error", c.registerTCP(20001).Error)
	assert.Equal(t, "internal error", c.registerUDP(30001).Error)

	_, ok := reg.LookupHTTP("some-name")
	assert.False(t, ok)
	_, ok = reg.LookupTCP(20001)
	assert.False(t, ok)
	_, ok = reg.LookupUDP(30001)
	assert.False(t, ok)
	assert.Equal(t, []int{20001}, tcp.closed(), "the opened listener is released again")
	assert.Equal(t, []int{30001}, udp.closed())
}

// ---- a second port of the same kind ----

func TestSecondTCPPortIsRejectedWithoutOpeningAListener(t *testing.T) {
	reg := registry.New()
	edge := &fakeEdge{}
	opts := staticOpts()
	opts.Registry = reg
	opts.TCPEdge = fakeTCPEdge{edge}
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, staticToken)

	first := c.registerTCP(0)
	require.Empty(t, first.Error)
	require.Equal(t, 40000, first.Port)
	assert.Equal(t, "tunnel.localhost:40000", first.PublicAddr)

	second := c.registerTCP(0)
	assert.Equal(t, "session already has a tcp port", second.Error)
	assert.Zero(t, second.Port)
	third := c.registerTCP(41000)
	assert.Equal(t, "session already has a tcp port", third.Error)

	assert.Equal(t, []int{0}, edge.opened(), "only the first request may reach the edge")
	assert.Empty(t, edge.closed())
	_, ok := reg.LookupTCP(40000)
	assert.True(t, ok, "the first tunnel is untouched")
}

func TestSecondUDPPortIsRejectedWithoutOpeningAListener(t *testing.T) {
	reg := registry.New()
	edge := &fakeEdge{}
	opts := staticOpts()
	opts.Registry = reg
	opts.UDPEdge = fakeUDPEdge{edge}
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, staticToken)

	first := c.registerUDP(0)
	require.Empty(t, first.Error)
	require.Equal(t, 40000, first.Port)
	assert.Equal(t, "tunnel.localhost:40000", first.PublicAddr)

	second := c.registerUDP(0)
	assert.Equal(t, "session already has a udp port", second.Error)
	assert.Zero(t, second.Port)

	assert.Equal(t, []int{0}, edge.opened())
	assert.Empty(t, edge.closed())
	_, ok := reg.LookupUDP(40000)
	assert.True(t, ok)
}

// The registry may have forgotten the session (an admin kill removes the
// entries before the session is gone). The session's own record still blocks
// a second listener, so the first port cannot be orphaned.
func TestSecondPortIsRejectedEvenWhenTheRegistryForgotTheFirst(t *testing.T) {
	reg := registry.New()
	tcp, udp := &fakeEdge{}, &fakeEdge{}
	opts := staticOpts()
	opts.Registry = reg
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, nil)
	c, hello := login(t, addr, staticToken)
	require.Empty(t, c.registerTCP(0).Error)
	require.Empty(t, c.registerUDP(0).Error)

	s, ok := reg.LookupTCP(40000)
	require.True(t, ok)
	require.Equal(t, hello.SessionID, s.ID())
	reg.Unregister(s) // what KillSession does first; the session itself stays up here

	assert.Equal(t, "session already has a tcp port", c.registerTCP(0).Error)
	assert.Equal(t, "session already has a udp port", c.registerUDP(0).Error)
	assert.Equal(t, []int{0}, tcp.opened())
	assert.Equal(t, []int{0}, udp.opened())
}

// ---- port numbers and reservations ----

func TestRegisterPortOutOfRangeIsRejectedBeforeAnythingElse(t *testing.T) {
	fx := newDBFixture(t)
	uid, raw := fx.user(t, "range@example.com")
	ctx := context.Background()
	// Port 80 is reserved for this user; 4294967376 has the same low 32 bits.
	require.NoError(t, fx.res.GrantTCPPort(ctx, 80, uid))
	require.NoError(t, fx.res.GrantUDPPort(ctx, 80, uid))
	tcp, udp := &fakeEdge{}, &fakeEdge{}
	opts := fx.dbOpts()
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	opts.ControlBurst = -1
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, raw)

	for _, port := range []int64{-1, -80, 65536, 70000, 4294967376} {
		assert.Equal(t, "port out of range", c.registerTCP(port).Error, "tcp port %d", port)
		assert.Equal(t, "port out of range", c.registerUDP(port).Error, "udp port %d", port)
	}
	assert.Empty(t, tcp.opened())
	assert.Empty(t, udp.opened())

	// 65535 is a valid number; here it is merely not reserved.
	assert.Equal(t, "port not reserved", c.registerTCP(65535).Error)
}

// The range check does not depend on reservations: static-token mode has it
// too, and nothing outside 0-65535 reaches the edge.
func TestRegisterPortOutOfRangeInStaticMode(t *testing.T) {
	tcp, udp := &fakeEdge{}, &fakeEdge{}
	opts := staticOpts()
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	opts.ControlBurst = -1
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, staticToken)

	for _, port := range []int64{-1, 65536, 4294967376} {
		assert.Equal(t, "port out of range", c.registerTCP(port).Error, "tcp port %d", port)
		assert.Equal(t, "port out of range", c.registerUDP(port).Error, "udp port %d", port)
	}
	assert.Empty(t, tcp.opened())
	assert.Empty(t, udp.opened())
}

func TestStaticModeAllowsASpecificPort(t *testing.T) {
	reg := registry.New()
	tcp, udp := &fakeEdge{}, &fakeEdge{}
	opts := staticOpts()
	opts.Registry = reg
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, staticToken)

	tcpAck := c.registerTCP(12345)
	require.Empty(t, tcpAck.Error)
	assert.Equal(t, 12345, tcpAck.Port)
	udpAck := c.registerUDP(65535)
	require.Empty(t, udpAck.Error)
	assert.Equal(t, 65535, udpAck.Port)

	assert.Equal(t, []int{12345}, tcp.opened())
	assert.Equal(t, []int{65535}, udp.opened())
	_, ok := reg.LookupTCP(12345)
	assert.True(t, ok)
	_, ok = reg.LookupUDP(65535)
	assert.True(t, ok)
}

func TestDatabaseModeSpecificPortMustBeReservedForTheUser(t *testing.T) {
	fx := newDBFixture(t)
	ctx := context.Background()
	me, raw := fx.user(t, "me@example.com")
	other, _ := fx.user(t, "them@example.com")
	require.NoError(t, fx.res.GrantTCPPort(ctx, 20002, other))
	require.NoError(t, fx.res.GrantTCPPort(ctx, 20003, me))
	require.NoError(t, fx.res.GrantUDPPort(ctx, 30002, other))
	require.NoError(t, fx.res.GrantUDPPort(ctx, 30003, me))
	// The TCP reservation of a number says nothing about UDP and vice versa.
	require.NoError(t, fx.res.GrantUDPPort(ctx, 20004, me))
	require.NoError(t, fx.res.GrantTCPPort(ctx, 30004, me))

	reg := registry.New()
	tcp, udp := &fakeEdge{}, &fakeEdge{}
	opts := fx.dbOpts()
	opts.Registry = reg
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, raw)

	assert.Equal(t, "port not reserved", c.registerTCP(20001).Error)
	assert.Equal(t, "port reserved", c.registerTCP(20002).Error)
	assert.Equal(t, "port not reserved", c.registerTCP(20004).Error, "reserved for UDP only")
	assert.Equal(t, "port not reserved", c.registerUDP(30001).Error)
	assert.Equal(t, "port reserved", c.registerUDP(30002).Error)
	assert.Equal(t, "port not reserved", c.registerUDP(30004).Error, "reserved for TCP only")
	assert.Empty(t, tcp.opened(), "a refused port never reaches the edge")
	assert.Empty(t, udp.opened())

	tcpAck := c.registerTCP(20003)
	require.Empty(t, tcpAck.Error)
	assert.Equal(t, 20003, tcpAck.Port)
	udpAck := c.registerUDP(30003)
	require.Empty(t, udpAck.Error)
	assert.Equal(t, 30003, udpAck.Port)
	assert.Equal(t, []int{20003}, tcp.opened())
	assert.Equal(t, []int{30003}, udp.opened())
	_, ok := reg.LookupTCP(20003)
	assert.True(t, ok)
	_, ok = reg.LookupUDP(30003)
	assert.True(t, ok)
}

// Database mode without a reservations service: nothing can be reserved for
// the user, so no specific port is allowed.
func TestDatabaseModeWithoutReservationsRefusesSpecificPorts(t *testing.T) {
	fx := newDBFixture(t)
	_, raw := fx.user(t, "nores@example.com")
	tcp, udp := &fakeEdge{}, &fakeEdge{}
	opts := fx.dbOpts()
	opts.Reservations = nil
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, raw)

	assert.Equal(t, "port not reserved", c.registerTCP(20001).Error)
	assert.Equal(t, "port not reserved", c.registerUDP(30001).Error)
	assert.Empty(t, tcp.opened())
	assert.Empty(t, udp.opened())

	// Port 0 still works.
	require.Empty(t, c.registerTCP(0).Error)
	require.Empty(t, c.registerUDP(0).Error)
}

func TestDrawnPortReservedForAnotherUserIsReleasedAndRedrawn(t *testing.T) {
	fx := newDBFixture(t)
	ctx := context.Background()
	_, raw := fx.user(t, "drawer@example.com")
	other, _ := fx.user(t, "holder@example.com")
	require.NoError(t, fx.res.GrantTCPPort(ctx, 41001, other))
	require.NoError(t, fx.res.GrantTCPPort(ctx, 41002, other))
	require.NoError(t, fx.res.GrantUDPPort(ctx, 42001, other))

	reg := registry.New()
	tcp := &fakeEdge{script: []openResult{{port: 41001}, {port: 41002}, {port: 41003}}}
	udp := &fakeEdge{script: []openResult{{port: 42001}, {port: 42002}}}
	opts := fx.dbOpts()
	opts.Registry = reg
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, raw)

	tcpAck := c.registerTCP(0)
	require.Empty(t, tcpAck.Error)
	assert.Equal(t, 41003, tcpAck.Port)
	assert.Equal(t, []int{0, 0, 0}, tcp.opened())
	assert.Equal(t, []int{41001, 41002}, tcp.closed(), "the foreign ports go back to the pool")
	for _, port := range []int{41001, 41002} {
		_, ok := reg.LookupTCP(port)
		assert.False(t, ok, "port %d must not stay registered", port)
	}
	_, ok := reg.LookupTCP(41003)
	assert.True(t, ok)

	udpAck := c.registerUDP(0)
	require.Empty(t, udpAck.Error)
	assert.Equal(t, 42002, udpAck.Port)
	assert.Equal(t, []int{42001}, udp.closed())
	_, ok = reg.LookupUDP(42001)
	assert.False(t, ok)
	_, ok = reg.LookupUDP(42002)
	assert.True(t, ok)
}

func TestDrawnPortReservedForTheSameUserIsKept(t *testing.T) {
	fx := newDBFixture(t)
	ctx := context.Background()
	me, raw := fx.user(t, "lucky@example.com")
	require.NoError(t, fx.res.GrantTCPPort(ctx, 41001, me))

	tcp := &fakeEdge{script: []openResult{{port: 41001}}}
	opts := fx.dbOpts()
	opts.TCPEdge = fakeTCPEdge{tcp}
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, raw)

	ack := c.registerTCP(0)
	require.Empty(t, ack.Error)
	assert.Equal(t, 41001, ack.Port)
	assert.Empty(t, tcp.closed())
}

func TestDrawingAPortGivesUpAfterEightAttempts(t *testing.T) {
	fx := newDBFixture(t)
	ctx := context.Background()
	_, raw := fx.user(t, "unlucky@example.com")
	other, _ := fx.user(t, "landlord@example.com")
	require.NoError(t, fx.res.GrantTCPPort(ctx, 41001, other))
	require.NoError(t, fx.res.GrantUDPPort(ctx, 42001, other))

	always := func(port int) []openResult {
		var s []openResult
		for i := 0; i < 50; i++ {
			s = append(s, openResult{port: port})
		}
		return s
	}
	reg := registry.New()
	tcp, udp := &fakeEdge{script: always(41001)}, &fakeEdge{script: always(42001)}
	opts := fx.dbOpts()
	opts.Registry = reg
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, raw)

	assert.Equal(t, "no ports available", c.registerTCP(0).Error)
	assert.Len(t, tcp.opened(), 8)
	assert.Len(t, tcp.closed(), 8, "every drawn port is released again")
	_, ok := reg.LookupTCP(41001)
	assert.False(t, ok)

	assert.Equal(t, "no ports available", c.registerUDP(0).Error)
	assert.Len(t, udp.opened(), 8)
	assert.Len(t, udp.closed(), 8)
	_, ok = reg.LookupUDP(42001)
	assert.False(t, ok)

	// The failed draws left the session free to try again.
	tcp.mu.Lock()
	tcp.script = []openResult{{port: 41009}}
	tcp.mu.Unlock()
	ack := c.registerTCP(0)
	require.Empty(t, ack.Error)
	assert.Equal(t, 41009, ack.Port)
}

// The reservation changes hands between the check and the registration: the
// check after the registration notices and rolls back.
func TestSpecificPortIsRolledBackWhenTheReservationChangesHands(t *testing.T) {
	fx := newDBFixture(t)
	ctx := context.Background()
	me, raw := fx.user(t, "racer@example.com")
	other, _ := fx.user(t, "winner@example.com")
	require.NoError(t, fx.res.GrantTCPPort(ctx, 20005, me))
	require.NoError(t, fx.res.GrantUDPPort(ctx, 30005, me))

	reg := registry.New()
	tcp := &fakeEdge{onOpen: func(int) {
		require.NoError(t, fx.res.RevokeTCPPort(ctx, 20005))
		require.NoError(t, fx.res.GrantTCPPort(ctx, 20005, other))
	}}
	udp := &fakeEdge{onOpen: func(int) {
		require.NoError(t, fx.res.RevokeUDPPort(ctx, 30005))
		require.NoError(t, fx.res.GrantUDPPort(ctx, 30005, other))
	}}
	opts := fx.dbOpts()
	opts.Registry = reg
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, raw)

	assert.Equal(t, "port reserved", c.registerTCP(20005).Error)
	assert.Equal(t, []int{20005}, tcp.opened())
	assert.Equal(t, []int{20005}, tcp.closed())
	_, ok := reg.LookupTCP(20005)
	assert.False(t, ok)

	assert.Equal(t, "port reserved", c.registerUDP(30005).Error)
	assert.Equal(t, []int{30005}, udp.closed())
	_, ok = reg.LookupUDP(30005)
	assert.False(t, ok)

	// Nothing is left on the session: it can still get ports.
	tcp.mu.Lock()
	tcp.onOpen = nil
	tcp.mu.Unlock()
	require.Empty(t, c.registerTCP(0).Error)
}

// A reservation that merely disappears between the two checks is not enough
// either: a specific port needs a reservation of its user at both times.
func TestSpecificPortIsRolledBackWhenTheReservationDisappears(t *testing.T) {
	fx := newDBFixture(t)
	ctx := context.Background()
	me, raw := fx.user(t, "revoked@example.com")
	require.NoError(t, fx.res.GrantTCPPort(ctx, 20006, me))

	reg := registry.New()
	tcp := &fakeEdge{onOpen: func(int) { require.NoError(t, fx.res.RevokeTCPPort(ctx, 20006)) }}
	opts := fx.dbOpts()
	opts.Registry = reg
	opts.TCPEdge = fakeTCPEdge{tcp}
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, raw)

	assert.Equal(t, "port not reserved", c.registerTCP(20006).Error)
	assert.Equal(t, []int{20006}, tcp.closed())
	_, ok := reg.LookupTCP(20006)
	assert.False(t, ok)
}

func TestNamedSubdomainIsRolledBackWhenItGetsReservedDuringRegistration(t *testing.T) {
	fx := newDBFixture(t)
	me, raw := fx.user(t, "namer@example.com")
	lookup := &fakeLookup{answer: func(_ string, call int) (int64, bool, error) {
		if call == 1 {
			return 0, false, nil // free when the request is checked
		}
		return me + 1000, true, nil // reserved for somebody else right after
	}}
	reg := registry.New()
	opts := fx.dbOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, func(a *Acceptor) { a.res = lookup })
	c, _ := login(t, addr, raw)

	ack := c.registerHTTP("contested-name")
	assert.Equal(t, "subdomain reserved", ack.Error)
	assert.Empty(t, ack.PublicURL)
	_, ok := reg.LookupHTTP("contested-name")
	assert.False(t, ok, "the registration must be rolled back")
	assert.Equal(t, 2, lookup.count("http"))

	// The session can register another name afterwards.
	lookup.mu.Lock()
	lookup.answer = func(string, int) (int64, bool, error) { return 0, false, nil }
	lookup.mu.Unlock()
	require.Empty(t, c.registerHTTP("second-try").Error)
}

func TestNamedSubdomainReservedForTheSameUserStaysRegistered(t *testing.T) {
	fx := newDBFixture(t)
	me, raw := fx.user(t, "selfowner@example.com")
	lookup := &fakeLookup{answer: func(string, int) (int64, bool, error) { return me, true, nil }}
	reg := registry.New()
	opts := fx.dbOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, func(a *Acceptor) { a.res = lookup })
	c, _ := login(t, addr, raw)

	require.Empty(t, c.registerHTTP("my-own-name").Error)
	_, ok := reg.LookupHTTP("my-own-name")
	assert.True(t, ok)
}

// ---- edge and registry errors ----

func TestEdgeErrorsBecomeFixedTexts(t *testing.T) {
	logger, logs := captureLogger()
	tcp := &fakeEdge{script: []openResult{
		{err: edgetcp.ErrPortOutOfRange},
		{err: edgetcp.ErrPortUnavailable},
		{err: edgetcp.ErrPoolExhausted},
		{err: fmt.Errorf("wrapped: %w", edgetcp.ErrPortUnavailable)},
		{err: errors.New("listen tcp :12345: bind: SECRET-TCP-DETAIL")},
	}}
	udp := &fakeEdge{script: []openResult{
		{err: edgeudp.ErrPortOutOfRange},
		{err: edgeudp.ErrPortUnavailable},
		{err: edgeudp.ErrPoolExhausted},
		{err: errors.New("listen udp :12345: bind: SECRET-UDP-DETAIL")},
	}}
	opts := staticOpts()
	opts.Logger = logger
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	opts.ControlBurst = -1
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, staticToken)

	assert.Equal(t, "port out of range", c.registerTCP(12345).Error)
	assert.Equal(t, "port unavailable", c.registerTCP(12345).Error)
	assert.Equal(t, "no ports available", c.registerTCP(0).Error)
	assert.Equal(t, "port unavailable", c.registerTCP(12345).Error)
	assert.Equal(t, "port unavailable", c.registerTCP(12345).Error)

	assert.Equal(t, "port out of range", c.registerUDP(12345).Error)
	assert.Equal(t, "port unavailable", c.registerUDP(12345).Error)
	assert.Equal(t, "no ports available", c.registerUDP(0).Error)
	assert.Equal(t, "port unavailable", c.registerUDP(12345).Error)

	assert.Empty(t, tcp.closed(), "a failed Open leaves nothing to close")
	assert.Empty(t, udp.closed())
	out := logs.String()
	assert.Contains(t, out, "SECRET-TCP-DETAIL", "the original error belongs in the server log")
	assert.Contains(t, out, "SECRET-UDP-DETAIL")
}

// The registry refuses a port the edge handed out: the listener is released
// and the client gets a fixed text.
func TestPortRefusedByTheRegistryIsReleased(t *testing.T) {
	reg := registry.New()
	squatter := &TunnelSession{id: "squatter"}
	require.NoError(t, reg.RegisterTCP(41001, squatter))
	require.NoError(t, reg.RegisterUDP(42001, squatter))

	tcp := &fakeEdge{script: []openResult{{port: 41001}}}
	udp := &fakeEdge{script: []openResult{{port: 42001}}}
	opts := staticOpts()
	opts.Registry = reg
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, staticToken)

	assert.Equal(t, "port unavailable", c.registerTCP(0).Error)
	assert.Equal(t, []int{41001}, tcp.closed())
	assert.Equal(t, "port unavailable", c.registerUDP(0).Error)
	assert.Equal(t, []int{42001}, udp.closed())

	s, ok := reg.LookupTCP(41001)
	require.True(t, ok)
	assert.Equal(t, "squatter", s.ID(), "the other session keeps its entry")
	s, ok = reg.LookupUDP(42001)
	require.True(t, ok)
	assert.Equal(t, "squatter", s.ID())
}

func TestTunnelingDisabledTexts(t *testing.T) {
	addr, _ := serve(t, staticOpts(), nil)
	c, _ := login(t, addr, staticToken)
	assert.Equal(t, "tcp tunneling disabled", c.registerTCP(0).Error)
	assert.Equal(t, "udp tunneling disabled", c.registerUDP(0).Error)
}

// A nil *Manager assigned to the interface fields is "no edge", not an edge
// to call.
func TestNilEdgeManagersMeanDisabled(t *testing.T) {
	opts := staticOpts()
	opts.TCPEdge = (*edgetcp.Manager)(nil)
	opts.UDPEdge = (*edgeudp.Manager)(nil)
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, staticToken)
	assert.Equal(t, "tcp tunneling disabled", c.registerTCP(0).Error)
	assert.Equal(t, "udp tunneling disabled", c.registerUDP(0).Error)
	c.requireOpen()
}

// ---- teardown order ----

func TestTeardownCleansTheRegistryBeforeReleasingPorts(t *testing.T) {
	reg := registry.New()
	var tcpStillRegistered, udpStillRegistered atomic.Int32
	tcp := &fakeEdge{onClose: func(port int) {
		if _, ok := reg.LookupTCP(port); ok {
			tcpStillRegistered.Add(1)
		}
	}}
	// Different numbers for the two protocols: a mix-up must show.
	udp := &fakeEdge{next: 500, onClose: func(port int) {
		if _, ok := reg.LookupUDP(port); ok {
			udpStillRegistered.Add(1)
		}
	}}
	opts := staticOpts()
	opts.Registry = reg
	opts.TCPEdge = fakeTCPEdge{tcp}
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, staticToken)
	require.Empty(t, c.registerHTTP("teardown").Error)
	require.Equal(t, 40000, c.registerTCP(0).Port)
	require.Equal(t, 40500, c.registerUDP(0).Port)

	require.NoError(t, c.sess.Close())

	require.Eventually(t, func() bool {
		return len(tcp.closed()) == 1 && len(udp.closed()) == 1
	}, waitFor, 20*time.Millisecond)
	assert.Equal(t, []int{40000}, tcp.closed())
	assert.Equal(t, []int{40500}, udp.closed())
	assert.Zero(t, tcpStillRegistered.Load(), "the TCP port was released while the registry still listed it")
	assert.Zero(t, udpStillRegistered.Load(), "the UDP port was released while the registry still listed it")
	assert.Empty(t, reg.SnapshotAll())
}

// A session that ends after its port went to somebody else must not remove
// the new owner's registry entry.
func TestTeardownLeavesAPortThatNowBelongsToAnotherSession(t *testing.T) {
	reg := registry.New()
	udp := &fakeEdge{}
	opts := staticOpts()
	opts.Registry = reg
	opts.UDPEdge = fakeUDPEdge{udp}
	addr, _ := serve(t, opts, nil)
	c, hello := login(t, addr, staticToken)
	require.Equal(t, 40000, c.registerUDP(0).Port)

	// An admin kill: the registry drops the session, a new session takes the
	// port, and only then does the old session finish its teardown.
	old, ok := reg.LookupUDP(40000)
	require.True(t, ok)
	require.Equal(t, hello.SessionID, old.ID())
	reg.Unregister(old)
	heir := &TunnelSession{id: "heir"}
	require.NoError(t, reg.RegisterUDP(40000, heir))

	require.NoError(t, c.sess.Close())
	require.Eventually(t, func() bool { return len(udp.closed()) == 1 }, waitFor, 20*time.Millisecond)

	s, ok := reg.LookupUDP(40000)
	require.True(t, ok, "the new owner's entry is gone")
	assert.Equal(t, "heir", s.ID())
}

// ---- sessions are tracked from the handshake ----

func TestSessionIsTrackedAndKillableRightAfterTheHandshake(t *testing.T) {
	fx := newDBFixture(t)
	uid, raw := fx.user(t, "tracked@example.com")
	reg := registry.New()
	opts := fx.dbOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)
	c, hello := login(t, addr, raw)

	snap := reg.SnapshotAll()
	require.Len(t, snap, 1, "a session without a tunnel is listed")
	assert.Equal(t, hello.SessionID, snap[0].SessionID)
	assert.Equal(t, "session", snap[0].Type)
	assert.Equal(t, uid, snap[0].Session.(registry.UserIDer).UserIDValue())
	assert.Equal(t, fx.tokenID(t, uid), snap[0].Session.(registry.TokenIDer).TokenIDValue(),
		"the session carries the ID of the token it logged in with")
	assert.WithinDuration(t, time.Now(), snap[0].Session.(registry.ConnectedAter).ConnectedAtValue(), 30*time.Second)

	require.True(t, reg.KillSession(hello.SessionID))
	c.requireClosed(waitFor)
	assert.Empty(t, reg.SnapshotAll())
}

func TestKillByUserEndsTheUsersTunnels(t *testing.T) {
	fx := newDBFixture(t)
	uid, raw := fx.user(t, "disabled@example.com")
	_, otherRaw := fx.user(t, "bystander@example.com")
	reg := registry.New()
	opts := fx.dbOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)

	withTunnel, _ := login(t, addr, raw)
	require.Empty(t, withTunnel.registerHTTP("doomed").Error)
	idle, _ := login(t, addr, raw)
	bystander, _ := login(t, addr, otherRaw)
	require.Empty(t, bystander.registerHTTP("survivor").Error)

	assert.Equal(t, 2, reg.KillByUser(uid))

	withTunnel.requireClosed(waitFor)
	idle.requireClosed(waitFor)
	bystander.requireOpen()
	_, ok := reg.LookupHTTP("doomed")
	assert.False(t, ok)
	_, ok = reg.LookupHTTP("survivor")
	assert.True(t, ok)
}

func TestAuthenticateReturnsUserAndTokenID(t *testing.T) {
	fx := newDBFixture(t)
	uid, raw := fx.user(t, "auth@example.com")
	ctx := context.Background()

	acc := New(fx.dbOpts())
	gotUser, gotToken, ok := acc.authenticate(ctx, raw)
	assert.True(t, ok)
	assert.Equal(t, uid, gotUser)
	assert.Equal(t, fx.tokenID(t, uid), gotToken)

	gotUser, gotToken, ok = acc.authenticate(ctx, "twbl_00000000000000000000000000000000")
	assert.False(t, ok)
	assert.Zero(t, gotUser)
	assert.Zero(t, gotToken)
	_, _, ok = acc.authenticate(ctx, "")
	assert.False(t, ok)

	static := New(staticOpts())
	gotUser, gotToken, ok = static.authenticate(ctx, staticToken)
	assert.True(t, ok)
	assert.Zero(t, gotUser)
	assert.Zero(t, gotToken)
	_, _, ok = static.authenticate(ctx, "twbl_wrong")
	assert.False(t, ok)
	_, _, ok = static.authenticate(ctx, "")
	assert.False(t, ok)
}
