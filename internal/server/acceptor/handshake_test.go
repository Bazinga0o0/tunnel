package acceptor

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeudp"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// ---- defaults and option handling ----

func TestNewResolvesDefaultLimits(t *testing.T) {
	acc := New(staticOpts())
	assert.Equal(t, limits{
		handshakeTimeout:    10 * time.Second,
		verifyTimeout:       5 * time.Second,
		maxUnauthConns:      256,
		maxUnauthConnsPerIP: 16,
		preAuthFrameSize:    4096,
		controlFrameSize:    16384,
		acceptBacklog:       32,
		maxStreams:          512,
		maxStreamsPerUser:   256,
		controlBurst:        20,
		controlRefill:       5,
		maxSessionsPerUser:  10,
		maxSessions:         350,
	}, acc.lim)
}

func TestNewKeepsExplicitLimits(t *testing.T) {
	opts := staticOpts()
	opts.HandshakeTimeout = 3 * time.Second
	opts.VerifyTimeout = 2 * time.Second
	opts.MaxUnauthConns = 7
	opts.MaxUnauthConnsPerIP = 3
	opts.MaxPreAuthFrameSize = 1000
	opts.MaxControlFrameSize = 2000
	opts.AcceptBacklog = 9
	opts.MaxStreamsPerSession = 11
	opts.MaxStreamsPerUser = 12
	opts.ControlBurst = 13
	opts.ControlRefillPerSecond = 2
	opts.MaxSessionsPerUser = 4
	opts.MaxSessions = 99
	assert.Equal(t, limits{
		handshakeTimeout:    3 * time.Second,
		verifyTimeout:       2 * time.Second,
		maxUnauthConns:      7,
		maxUnauthConnsPerIP: 3,
		preAuthFrameSize:    1000,
		controlFrameSize:    2000,
		acceptBacklog:       9,
		maxStreams:          11,
		maxStreamsPerUser:   12,
		controlBurst:        13,
		controlRefill:       2,
		maxSessionsPerUser:  4,
		maxSessions:         99,
	}, New(opts).lim)
}

// A negative value disables a limit. Inside the acceptor "disabled" is 0,
// except for the frame sizes (the protocol ceiling of 1 MiB remains) and the
// backlog (passed on as it is; the protocol package then keeps yamux's 256).
func TestNewDisablesLimitsForNegativeValues(t *testing.T) {
	opts := staticOpts()
	opts.HandshakeTimeout = -1
	opts.VerifyTimeout = -1
	opts.MaxUnauthConns = -1
	opts.MaxUnauthConnsPerIP = -1
	opts.MaxPreAuthFrameSize = -1
	opts.MaxControlFrameSize = -1
	opts.AcceptBacklog = -1
	opts.MaxStreamsPerSession = -1
	opts.MaxStreamsPerUser = -1
	opts.ControlBurst = -1
	opts.ControlRefillPerSecond = -1
	opts.MaxSessionsPerUser = -1
	opts.MaxSessions = -1
	assert.Equal(t, limits{
		preAuthFrameSize: 1 << 20,
		controlFrameSize: 1 << 20,
		acceptBacklog:    -1,
	}, New(opts).lim)
}

func TestAcceptorPassesAcceptBacklogToTheSession(t *testing.T) {
	for _, tc := range []struct{ option, want int }{{0, 32}, {7, 7}, {-1, -1}} {
		t.Run(fmt.Sprint(tc.option), func(t *testing.T) {
			opts := staticOpts()
			opts.AcceptBacklog = tc.option
			got := make(chan protocol.ServerOptions, 4)
			addr, _ := serve(t, opts, func(a *Acceptor) {
				inner := a.newSession
				a.newSession = func(conn io.ReadWriteCloser, o protocol.ServerOptions) (protocol.Session, error) {
					got <- o
					return inner(conn, o)
				}
			})
			login(t, addr, staticToken)
			select {
			case o := <-got:
				assert.Equal(t, tc.want, o.AcceptBacklog)
			case <-time.After(waitFor):
				t.Fatal("no session was created")
			}
		})
	}
}

// ---- handshake deadline ----

// requireClosedAtDeadline checks when the server ended a connection that the
// test opened after start. The server starts its clock at accept, which is
// later than start, so the connection cannot have ended before start+deadline
// on any machine, however loaded. The upper bound leaves five seconds for a
// loaded machine and still lies below the default deadline of 10 s, which a
// server that ignored the configured value would apply.
func requireClosedAtDeadline(t *testing.T, start time.Time, deadline time.Duration) {
	t.Helper()
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, deadline, "closed before the deadline")
	assert.Less(t, elapsed, deadline+5*time.Second, "closed long after the deadline")
}

func TestHandshakeDeadlineClosesSilentTCPConnection(t *testing.T) {
	const deadline = 2 * time.Second
	opts := staticOpts()
	opts.HandshakeTimeout = deadline
	addr, _ := serve(t, opts, nil)

	start := time.Now()
	conn := dialRaw(t, addr)
	requireConnClosed(t, conn, waitFor)
	requireClosedAtDeadline(t, start, deadline)
}

// The acceptor runs the TLS handshake itself: a peer that does not speak TLS
// is turned away there, at once, and the log says so.
func TestConnectionThatIsNotTLSFailsInTheHandshake(t *testing.T) {
	logger, logs := captureLogger()
	opts := staticOpts()
	opts.Logger = logger
	opts.HandshakeTimeout = 60 * time.Second
	addr, _ := serve(t, opts, nil)

	conn := dialRaw(t, addr)
	_, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example\r\n\r\n"))
	require.NoError(t, err)
	// The server may answer with a TLS alert before it closes; read to the end.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(waitFor)))
	_, err = io.Copy(io.Discard, conn)
	require.False(t, isTimeout(err), "the connection stayed open: %v", err)

	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "tls handshake failed") },
		waitFor, 20*time.Millisecond, "log: %s", logs.String())
}

func TestHandshakeDeadlineClosesSessionThatSendsNoHello(t *testing.T) {
	const deadline = 3 * time.Second
	opts := staticOpts()
	opts.HandshakeTimeout = deadline
	addr, _ := serve(t, opts, nil)

	start := time.Now()
	c := connect(t, addr) // TLS and yamux are up, the control stream is open
	c.requireClosed(waitFor)
	requireClosedAtDeadline(t, start, deadline)
}

// A client that starts a frame and then stalls gets no extension.
func TestHandshakeDeadlineClosesSessionWithHalfAHello(t *testing.T) {
	const deadline = 3 * time.Second
	opts := staticOpts()
	opts.HandshakeTimeout = deadline
	addr, _ := serve(t, opts, nil)

	start := time.Now()
	c := connect(t, addr)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 100)
	_, err := c.ctrl.Write(append(hdr[:], []byte(`{"type":"hel`)...))
	require.NoError(t, err)
	// The read of the rest of the frame is under the same deadline.
	c.requireClosed(waitFor)
	requireClosedAtDeadline(t, start, deadline)
}

func TestHandshakeDeadlineIsLiftedAfterHelloAck(t *testing.T) {
	const deadline = 3 * time.Second
	opts := staticOpts()
	opts.HandshakeTimeout = deadline
	reg := registry.New()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)

	c, _ := login(t, addr, staticToken)
	// The server's clock started before the login was complete, so a full
	// deadline from now is certainly past the moment it would have fired.
	time.Sleep(deadline + 500*time.Millisecond)
	c.requireOpen()
	ack := c.registerHTTP("after-deadline")
	require.Empty(t, ack.Error)
	_, ok := reg.LookupHTTP("after-deadline")
	assert.True(t, ok)
}

// A rejected login does not lift the deadline either: the connection ends.
func TestRejectedLoginEndsTheConnection(t *testing.T) {
	addr, _ := serve(t, staticOpts(), nil)
	c := connect(t, addr)
	ack := c.hello("twbl_wrong")
	assert.Equal(t, "invalid token", ack.Error)
	assert.Empty(t, ack.SessionID)
	c.requireClosed(waitFor)
}

func TestMessageBeforeHelloEndsTheConnection(t *testing.T) {
	reg := registry.New()
	opts := staticOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)
	c := connect(t, addr)
	c.sendEnding(protocol.TypeRegisterHTTP, protocol.RegisterHTTP{Subdomain: "sneaky"})
	c.requireClosed(waitFor)
	_, ok := reg.LookupHTTP("sneaky")
	assert.False(t, ok)
	assert.Empty(t, reg.SnapshotAll())
}

// Malformed input before the login ends the connection without an answer.
func TestMalformedHelloEndsTheConnection(t *testing.T) {
	frames := map[string][]byte{
		"empty frame":          {},
		"not json":             []byte("hello?"),
		"token is a number":    []byte(`{"type":"hello","payload":{"token":123}}`),
		"payload is a string":  []byte(`{"type":"hello","payload":"twbl_ok"}`),
		"payload missing":      []byte(`{"type":"hello"}`),
		"type is a number":     []byte(`{"type":7,"payload":{"token":"twbl_ok"}}`),
		"envelope is an array": []byte(`["hello"]`),
	}
	reg := registry.New()
	opts := staticOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)
	for name, frame := range frames {
		t.Run(name, func(t *testing.T) {
			c := connect(t, addr)
			c.writeFrameEnding(frame)
			c.requireClosed(waitFor)
		})
	}
	assert.Empty(t, reg.SnapshotAll())
}

// After the login a frame that is not a message ends the session; a message
// with a broken payload gets an error answer and the session goes on.
func TestMalformedControlMessages(t *testing.T) {
	addr, _ := serve(t, staticOpts(), nil)

	c, _ := login(t, addr, staticToken)
	require.NoError(t, protocol.WriteFrame(c.ctrl, []byte(`{"type":"register_http","payload":{"subdomain":5}}`)))
	var ack protocol.RegisterHTTPAck
	c.mustRecv(protocol.TypeRegisterHTTPAck, &ack)
	assert.Equal(t, "bad payload", ack.Error)
	require.NoError(t, protocol.WriteFrame(c.ctrl, []byte(`{"type":"register_tcp","payload":{"port":"80"}}`)))
	var tcpAck protocol.RegisterTCPAck
	c.mustRecv(protocol.TypeRegisterTCPAck, &tcpAck)
	assert.Equal(t, "bad payload", tcpAck.Error)
	require.NoError(t, protocol.WriteFrame(c.ctrl, []byte(`{"type":"register_udp","payload":{"port":1.5}}`)))
	var udpAck protocol.RegisterUDPAck
	c.mustRecv(protocol.TypeRegisterUDPAck, &udpAck)
	assert.Equal(t, "bad payload", udpAck.Error)
	c.requireOpen()

	c.writeFrameEnding([]byte("not json"))
	c.requireClosed(waitFor)

	c, _ = login(t, addr, staticToken)
	c.writeFrameEnding(nil)
	c.requireClosed(waitFor)
}

// ---- unauthenticated connection limits ----

func tcpAddr(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000} }

func TestConnLimiterDefaultsFromNew(t *testing.T) {
	l := New(staticOpts()).unauth

	// 16 from one address are admitted, the 17th is not.
	var releases []func()
	for i := 0; i < 16; i++ {
		release, ok := l.acquire(tcpAddr("198.51.100.1"))
		require.True(t, ok, "connection %d", i+1)
		releases = append(releases, release)
	}
	_, ok := l.acquire(tcpAddr("198.51.100.1"))
	require.False(t, ok, "17th connection from one address")

	// 256 in total are admitted (16 addresses with 16 each), the 257th is not.
	for a := 2; a <= 16; a++ {
		for i := 0; i < 16; i++ {
			release, ok := l.acquire(tcpAddr(fmt.Sprintf("198.51.100.%d", a)))
			require.True(t, ok, "address %d connection %d", a, i+1)
			releases = append(releases, release)
		}
	}
	require.Len(t, releases, 256)
	_, ok = l.acquire(tcpAddr("203.0.113.77"))
	require.False(t, ok, "257th connection in total")

	// Releasing one slot admits exactly one more.
	releases[0]()
	releases[0]() // releasing twice frees one slot only
	release, ok := l.acquire(tcpAddr("203.0.113.77"))
	require.True(t, ok)
	_, ok = l.acquire(tcpAddr("203.0.113.78"))
	require.False(t, ok)
	release()

	// Nothing is kept for addresses without a connection.
	for _, r := range releases {
		r()
	}
	assert.Zero(t, l.total)
	assert.Empty(t, l.perIP)
}

func TestConnLimiterGroupsAddresses(t *testing.T) {
	l := newConnLimiter(0, 1)

	_, ok := l.acquire(tcpAddr("192.0.2.1"))
	require.True(t, ok)
	_, ok = l.acquire(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1})
	assert.False(t, ok, "the port does not make a new source")
	_, ok = l.acquire(tcpAddr("::ffff:192.0.2.1"))
	assert.False(t, ok, "an IPv4-mapped address is the IPv4 address")
	_, ok = l.acquire(tcpAddr("192.0.2.2"))
	assert.True(t, ok, "another IPv4 address is another source")

	// One IPv6 /64 is one source: a host picks the lower 64 bits freely.
	_, ok = l.acquire(tcpAddr("2001:db8:1:2::1"))
	require.True(t, ok)
	_, ok = l.acquire(tcpAddr("2001:db8:1:2:ffff:ffff:ffff:ffff"))
	assert.False(t, ok, "same /64")
	_, ok = l.acquire(tcpAddr("2001:db8:1:3::1"))
	assert.True(t, ok, "another /64")

	// Addresses that cannot be parsed share one bucket instead of escaping.
	_, ok = l.acquire(pipeAddr{})
	require.True(t, ok)
	_, ok = l.acquire(pipeAddr{})
	assert.False(t, ok)
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func TestConnLimiterWithoutLimits(t *testing.T) {
	l := newConnLimiter(0, 0)
	for i := 0; i < 1000; i++ {
		_, ok := l.acquire(tcpAddr("192.0.2.1"))
		require.True(t, ok)
	}
}

func TestUnauthenticatedConnectionsOverTheTotalLimitAreClosedAtOnce(t *testing.T) {
	opts := staticOpts()
	opts.MaxUnauthConns = 2
	opts.MaxUnauthConnsPerIP = -1
	opts.HandshakeTimeout = 30 * time.Second
	addr, _ := serve(t, opts, nil)

	first, second := dialRaw(t, addr), dialRaw(t, addr)
	third := dialRaw(t, addr)
	requireConnClosed(t, third, waitFor)
	requireConnOpen(t, first, 100*time.Millisecond)
	requireConnOpen(t, second, 100*time.Millisecond)

	// A connection that goes away frees its slot.
	require.NoError(t, first.Close())
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return false
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		_, err = conn.Read(make([]byte, 1))
		return isTimeout(err) // open: the server did not turn it away
	}, waitFor, 50*time.Millisecond)
}

func TestUnauthenticatedConnectionsOverThePerIPLimitAreClosedAtOnce(t *testing.T) {
	opts := staticOpts()
	opts.MaxUnauthConns = -1
	opts.MaxUnauthConnsPerIP = 2
	opts.HandshakeTimeout = 30 * time.Second
	addr, _ := serve(t, opts, nil)

	first, second := dialRaw(t, addr), dialRaw(t, addr)
	third := dialRaw(t, addr)
	requireConnClosed(t, third, waitFor)
	requireConnOpen(t, first, 100*time.Millisecond)
	requireConnOpen(t, second, 100*time.Millisecond)

	// The limit is per source: another loopback address still gets in. (Not
	// every system lets a test bind 127.0.0.2; TestConnLimiterGroupsAddresses
	// covers the grouping without the network.)
	d := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
	fromElsewhere, err := d.Dial("tcp", addr)
	if err != nil {
		t.Logf("cannot dial from 127.0.0.2, skipping the second source: %v", err)
		return
	}
	defer fromElsewhere.Close()
	requireConnOpen(t, fromElsewhere, 200*time.Millisecond)
}

// Authenticated sessions do not use up the allowance for unauthenticated
// connections: with a limit of 1, three sessions can be up at the same time
// and a fourth client can still connect.
func TestAuthenticatedSessionsDoNotCountAsUnauthenticated(t *testing.T) {
	opts := staticOpts()
	opts.MaxUnauthConns = 1
	opts.HandshakeTimeout = 30 * time.Second
	addr, acc := serve(t, opts, nil)

	var clients []*client
	for i := 0; i < 3; i++ {
		c, _ := login(t, addr, staticToken)
		clients = append(clients, c)
	}
	for _, c := range clients {
		c.requireOpen()
	}
	acc.unauth.mu.Lock()
	total := acc.unauth.total
	acc.unauth.mu.Unlock()
	assert.Zero(t, total, "no unauthenticated connection is open")

	// One more unauthenticated connection fits, a second one does not.
	held := dialRaw(t, addr)
	requireConnOpen(t, held, 150*time.Millisecond)
	requireConnClosed(t, dialRaw(t, addr), waitFor)
}

// Connections over the limit get one log line per second, not one each.
func TestEventLogSpacesOutLines(t *testing.T) {
	e := eventLog{interval: time.Second}
	t0 := time.Unix(1_700_000_000, 0)

	logNow, events := e.note(t0)
	assert.True(t, logNow, "the first event is logged")
	assert.Equal(t, 1, events)

	logNow, _ = e.note(t0.Add(400 * time.Millisecond))
	assert.False(t, logNow)
	logNow, _ = e.note(t0.Add(999 * time.Millisecond))
	assert.False(t, logNow)

	logNow, events = e.note(t0.Add(time.Second))
	assert.True(t, logNow, "one interval later the next line is due")
	assert.Equal(t, 3, events, "the line stands for the two silent events and this one")

	logNow, _ = e.note(t0.Add(1500 * time.Millisecond))
	assert.False(t, logNow)
}

func TestConnectionsOverTheLimitAreLoggedOncePerSecond(t *testing.T) {
	logger, logs := captureLogger()
	opts := staticOpts()
	opts.Logger = logger
	opts.MaxUnauthConns = 1
	opts.HandshakeTimeout = 30 * time.Second
	addr, _ := serve(t, opts, nil)

	held := dialRaw(t, addr)
	requireConnOpen(t, held, 100*time.Millisecond)
	start := time.Now()
	for i := 0; i < 5; i++ {
		requireConnClosed(t, dialRaw(t, addr), waitFor)
	}
	elapsed := time.Since(start)
	const line = "unauthenticated connection limit reached"
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), line) }, waitFor, 20*time.Millisecond)
	// One line at once and then at most one per started second: two lines
	// when the five refusals take less than a second, as they normally do.
	allowed := 2 + int(elapsed/time.Second)
	assert.LessOrEqual(t, strings.Count(logs.String(), line), allowed,
		"five refusals in %s must not give more than %d lines", elapsed, allowed)
}

// ---- token verifier timeout ----

func TestTokenVerificationTimesOut(t *testing.T) {
	fx := newDBFixture(t)
	_, raw := fx.user(t, "slow@example.com")
	opts := fx.dbOpts()
	// Far enough below DefaultVerifyTimeout (5 s) that the time to the
	// answer tells the two apart.
	const verifyTimeout = time.Second
	opts.VerifyTimeout = verifyTimeout
	opts.HandshakeTimeout = 60 * time.Second
	addr, _ := serve(t, opts, nil)

	// Hold a lock that makes every token lookup wait.
	ctx := context.Background()
	lockConn, err := pgx.Connect(ctx, dbURL(t))
	require.NoError(t, err)
	defer lockConn.Close(ctx)
	tx, err := lockConn.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, "LOCK TABLE api_tokens IN ACCESS EXCLUSIVE MODE")
	require.NoError(t, err)

	// The lock is held until after the answer has arrived: an answer at all
	// proves that the verifier call was cut short.
	c := connect(t, addr)
	start := time.Now()
	require.NoError(t, c.send(protocol.TypeHello, protocol.Hello{Token: raw}))
	var ack protocol.HelloAck
	env, err := c.recv(waitFor)
	elapsed := time.Since(start)
	require.NoError(t, err, "the verifier call was not bounded")
	require.Equal(t, protocol.TypeHelloAck, env.Type)
	require.NoError(t, json.Unmarshal(env.Payload, &ack))
	assert.Equal(t, "invalid token", ack.Error, "a verifier that cannot answer in time denies")
	// The configured timeout, not the default: the answer comes after one
	// second and well before five. The clock starts before the hello is
	// sent, so the lower bound holds on any machine; the upper one leaves
	// three seconds for a loaded one.
	assert.GreaterOrEqual(t, elapsed, verifyTimeout, "the verifier was cut short before the configured timeout")
	assert.Less(t, elapsed, 4*time.Second, "the configured verify timeout was not used (the default is 5 s)")

	// With the lock gone the same token works.
	require.NoError(t, tx.Rollback(ctx))
	login(t, addr, raw)
}

// ---- extra streams ----

func TestExtraStreamAfterLoginClosesTheSession(t *testing.T) {
	reg := registry.New()
	opts := staticOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)

	c, _ := login(t, addr, staticToken)
	require.Empty(t, c.registerHTTP("extra-stream").Error)

	extra, err := c.sess.OpenStream()
	requireSentOrShutdown(t, err)
	if err == nil {
		_, _ = extra.Write([]byte("hello"))
	}

	c.requireClosed(waitFor)
	require.Eventually(t, func() bool { return len(reg.SnapshotAll()) == 0 }, waitFor, 20*time.Millisecond,
		"the closed session must leave the registry")
}

func TestExtraStreamBeforeHelloClosesTheConnection(t *testing.T) {
	addr, _ := serve(t, staticOpts(), nil)
	c := connect(t, addr)
	c.openEnding()
	c.requireClosed(waitFor)
}

// ---- control frame limits ----

// sendTooLarge writes a frame the server is expected to refuse. The server
// turns the frame away when it has read the length prefix, so the rest of
// the write may already fail; that failure is part of the refusal.
func (c *client) sendTooLarge(frame []byte) {
	_ = protocol.WriteFrame(c.ctrl, frame)
}

// helloOfSize returns a valid hello envelope that is exactly size bytes long.
func helloOfSize(t *testing.T, size int) []byte {
	t.Helper()
	base := len(envelope(protocol.TypeHello, protocol.Hello{Token: staticToken, OS: "test"}))
	require.Greater(t, size, base)
	b := envelope(protocol.TypeHello, protocol.Hello{Token: staticToken, OS: "test", ClientVersion: strings.Repeat("v", size-base)})
	require.Len(t, b, size)
	return b
}

// paddedOfSize returns an envelope of the given type that is exactly size
// bytes long; the padding sits in a payload field the server ignores.
func paddedOfSize(t *testing.T, typ protocol.MessageType, size int) []byte {
	t.Helper()
	base := len(envelope(typ, map[string]string{"pad": ""}))
	require.Greater(t, size, base)
	b := envelope(typ, map[string]string{"pad": strings.Repeat("p", size-base)})
	require.Len(t, b, size)
	return b
}

func TestHelloFrameOf4096BytesIsAccepted(t *testing.T) {
	addr, _ := serve(t, staticOpts(), nil)
	c := connect(t, addr)
	require.NoError(t, protocol.WriteFrame(c.ctrl, helloOfSize(t, 4096)))
	var ack protocol.HelloAck
	c.mustRecv(protocol.TypeHelloAck, &ack)
	assert.Empty(t, ack.Error)
	assert.NotEmpty(t, ack.SessionID)
}

func TestHelloFrameOf4097BytesIsRejected(t *testing.T) {
	reg := registry.New()
	opts := staticOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)
	c := connect(t, addr)
	c.sendTooLarge(helloOfSize(t, 4097))
	c.requireClosed(waitFor)
	assert.Empty(t, reg.SnapshotAll())
}

func TestControlFrameOf16384BytesIsAcceptedAfterLogin(t *testing.T) {
	addr, _ := serve(t, staticOpts(), nil)
	c, _ := login(t, addr, staticToken)
	require.NoError(t, protocol.WriteFrame(c.ctrl, paddedOfSize(t, protocol.TypeRegisterHTTP, 16384)))
	var ack protocol.RegisterHTTPAck
	c.mustRecv(protocol.TypeRegisterHTTPAck, &ack)
	assert.Empty(t, ack.Error)
	assert.Len(t, ack.Subdomain, 6)
}

func TestControlFrameOf16385BytesClosesTheSession(t *testing.T) {
	addr, _ := serve(t, staticOpts(), nil)
	c, _ := login(t, addr, staticToken)
	c.sendTooLarge(paddedOfSize(t, protocol.TypePing, 16385))
	c.requireClosed(waitFor)
}

// The length prefix alone is enough to be turned away: the server does not
// wait for (or allocate) the announced body.
func TestOversizedLengthPrefixIsRejectedBeforeTheBodyArrives(t *testing.T) {
	opts := staticOpts()
	opts.HandshakeTimeout = 60 * time.Second
	addr, _ := serve(t, opts, nil)
	c := connect(t, addr)
	_, err := c.ctrl.Write([]byte{0xff, 0xff, 0xff, 0xff})
	requireSentOrShutdown(t, err)
	c.requireClosed(waitFor)
}

func TestConfiguredFrameSizesAreEnforced(t *testing.T) {
	opts := staticOpts()
	opts.MaxPreAuthFrameSize = 200
	opts.MaxControlFrameSize = 300
	addr, _ := serve(t, opts, nil)

	c := connect(t, addr)
	c.sendTooLarge(helloOfSize(t, 201))
	c.requireClosed(waitFor)

	c = connect(t, addr)
	require.NoError(t, protocol.WriteFrame(c.ctrl, helloOfSize(t, 200)))
	var ack protocol.HelloAck
	c.mustRecv(protocol.TypeHelloAck, &ack)
	require.Empty(t, ack.Error)
	require.NoError(t, protocol.WriteFrame(c.ctrl, paddedOfSize(t, protocol.TypePing, 300)))
	c.mustRecv(protocol.TypePong, nil)
	c.sendTooLarge(paddedOfSize(t, protocol.TypePing, 301))
	c.requireClosed(waitFor)
}

// ---- session limits ----

func TestSessionLimitPerUserDefaultIsTen(t *testing.T) {
	fx := newDBFixture(t)
	uid, raw := fx.user(t, "ten@example.com")
	_, otherRaw := fx.user(t, "other@example.com")
	reg := registry.New()
	opts := fx.dbOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, nil)

	for i := 0; i < 10; i++ {
		login(t, addr, raw)
	}
	c := connect(t, addr)
	ack := c.hello(raw)
	assert.Equal(t, "session limit reached", ack.Error)
	assert.Empty(t, ack.SessionID)
	c.requireClosed(waitFor)

	// The limit is per user, and the rejected session is not tracked.
	login(t, addr, otherRaw)
	mine := 0
	for _, e := range reg.SnapshotAll() {
		if e.Session.(registry.UserIDer).UserIDValue() == uid {
			mine++
		}
	}
	assert.Equal(t, 10, mine)
}

func TestSessionLimitPerUserFreesUpWhenASessionEnds(t *testing.T) {
	fx := newDBFixture(t)
	_, raw := fx.user(t, "two@example.com")
	opts := fx.dbOpts()
	opts.MaxSessionsPerUser = 2
	addr, _ := serve(t, opts, nil)

	first, _ := login(t, addr, raw)
	login(t, addr, raw)
	require.Equal(t, "session limit reached", connect(t, addr).hello(raw).Error)

	require.NoError(t, first.sess.Close())
	require.Eventually(t, func() bool {
		return connect(t, addr).hello(raw).Error == ""
	}, waitFor, 50*time.Millisecond)
	require.Equal(t, "session limit reached", connect(t, addr).hello(raw).Error)
}

func TestSessionLimitTotal(t *testing.T) {
	reg := registry.New()
	opts := staticOpts()
	opts.Registry = reg
	opts.MaxSessions = 2
	opts.MaxSessionsPerUser = 1 // static-token sessions have no user: not applied
	addr, _ := serve(t, opts, nil)

	login(t, addr, staticToken)
	login(t, addr, staticToken)
	c := connect(t, addr)
	ack := c.hello(staticToken)
	assert.Equal(t, "server at capacity", ack.Error)
	assert.Empty(t, ack.SessionID)
	c.requireClosed(waitFor)
	assert.Len(t, reg.SnapshotAll(), 2)
}

// The acceptor hands its limits to the registry in the registry's terms: a
// disabled limit travels as a negative number, never as the zero that selects
// the registry's own default.
func TestSessionLimitsHandedToTheRegistry(t *testing.T) {
	assert.Equal(t, registry.SessionLimits{PerUser: 10, Total: 350}, New(staticOpts()).lim.sessionLimits())

	opts := staticOpts()
	opts.MaxSessionsPerUser = 4
	opts.MaxSessions = 99
	assert.Equal(t, registry.SessionLimits{PerUser: 4, Total: 99}, New(opts).lim.sessionLimits())

	opts.MaxSessionsPerUser = -1
	opts.MaxSessions = -1
	assert.Equal(t, registry.SessionLimits{PerUser: -1, Total: -1}, New(opts).lim.sessionLimits())
}

func TestSessionLimitPerUserCanBeDisabled(t *testing.T) {
	fx := newDBFixture(t)
	_, raw := fx.user(t, "unlimited@example.com")
	opts := fx.dbOpts()
	opts.MaxSessionsPerUser = -1
	addr, _ := serve(t, opts, nil)

	// More than the default of 10.
	for i := 0; i < 12; i++ {
		c := connect(t, addr)
		require.Empty(t, c.hello(raw).Error, "session %d", i+1)
	}
}

// ---- control message throttle ----

func TestTokenBucket(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	b := newTokenBucket(20, 5, t0)
	for i := 0; i < 20; i++ {
		require.True(t, b.allow(t0), "message %d of the burst", i+1)
	}
	require.False(t, b.allow(t0), "21st message at once")

	// 5 per second: 199 ms are not enough for one token, 200 ms are.
	require.False(t, b.allow(t0.Add(199*time.Millisecond)))
	require.True(t, b.allow(t0.Add(200*time.Millisecond)))
	require.False(t, b.allow(t0.Add(200*time.Millisecond)))

	// One second later five more, not six.
	t1 := t0.Add(1200 * time.Millisecond)
	for i := 0; i < 5; i++ {
		require.True(t, b.allow(t1), "refilled message %d", i+1)
	}
	require.False(t, b.allow(t1))

	// A long pause refills to the burst and no further.
	t2 := t1.Add(time.Hour)
	for i := 0; i < 20; i++ {
		require.True(t, b.allow(t2), "message %d after the pause", i+1)
	}
	require.False(t, b.allow(t2))

	// A clock that steps back takes nothing away and gives nothing.
	require.False(t, b.allow(t2.Add(-time.Minute)))
	require.False(t, b.allow(t2))
}

// A bucket that is almost full does not fill beyond the burst: one token
// used, then a second that would add five, leaves 20 and not 24.
func TestTokenBucketPartialRefillStopsAtTheBurst(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	b := newTokenBucket(20, 5, t0)
	require.True(t, b.allow(t0))

	t1 := t0.Add(time.Second)
	for i := 0; i < 20; i++ {
		require.True(t, b.allow(t1), "message %d", i+1)
	}
	require.False(t, b.allow(t1), "21st message")
}

func TestTokenBucketDisabled(t *testing.T) {
	var b *tokenBucket = newTokenBucket(0, 5, time.Now())
	require.Nil(t, b)
	for i := 0; i < 1000; i++ {
		require.True(t, b.allow(time.Now()))
	}
}

// frozenClock makes the throttle deterministic: no time passes unless the
// test says so.
type frozenClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *frozenClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *frozenClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestControlFloodClosesTheSessionAfterTheBurstOf20(t *testing.T) {
	clock := &frozenClock{now: time.Unix(1_700_000_000, 0)}
	addr, _ := serve(t, staticOpts(), func(a *Acceptor) { a.now = clock.Now })
	c, _ := login(t, addr, staticToken)

	for i := 0; i < 20; i++ {
		require.NoError(t, c.send(protocol.TypePing, nil))
		c.mustRecv(protocol.TypePong, nil)
	}
	c.sendEnding(protocol.TypePing, nil)
	c.requireClosed(waitFor)
}

func TestControlThrottleRefillsFivePerSecond(t *testing.T) {
	clock := &frozenClock{now: time.Unix(1_700_000_000, 0)}
	addr, _ := serve(t, staticOpts(), func(a *Acceptor) { a.now = clock.Now })
	c, _ := login(t, addr, staticToken)

	for i := 0; i < 20; i++ {
		c.requireOpen()
	}
	clock.advance(time.Second)
	for i := 0; i < 5; i++ {
		c.requireOpen()
	}
	c.sendEnding(protocol.TypePing, nil)
	c.requireClosed(waitFor)
}

func TestControlThrottleHonoursOptions(t *testing.T) {
	clock := &frozenClock{now: time.Unix(1_700_000_000, 0)}
	opts := staticOpts()
	opts.ControlBurst = 3
	opts.ControlRefillPerSecond = 1
	addr, _ := serve(t, opts, func(a *Acceptor) { a.now = clock.Now })
	c, _ := login(t, addr, staticToken)

	for i := 0; i < 3; i++ {
		c.requireOpen()
	}
	clock.advance(time.Second)
	c.requireOpen()
	c.sendEnding(protocol.TypePing, nil)
	c.requireClosed(waitFor)
}

func TestControlThrottleCanBeDisabled(t *testing.T) {
	clock := &frozenClock{now: time.Unix(1_700_000_000, 0)}
	opts := staticOpts()
	opts.ControlBurst = -1
	addr, _ := serve(t, opts, func(a *Acceptor) { a.now = clock.Now })
	c, _ := login(t, addr, staticToken)
	for i := 0; i < 60; i++ {
		c.requireOpen()
	}
}

// Register messages count against the throttle like pings do.
func TestRegisterMessagesAreThrottled(t *testing.T) {
	clock := &frozenClock{now: time.Unix(1_700_000_000, 0)}
	opts := staticOpts()
	opts.ControlBurst = 2
	addr, _ := serve(t, opts, func(a *Acceptor) { a.now = clock.Now })
	c, _ := login(t, addr, staticToken)

	require.Empty(t, c.registerHTTP("first-name").Error)
	require.Equal(t, "session already has a subdomain", c.registerHTTP("second-name").Error)
	c.sendEnding(protocol.TypeRegisterHTTP, protocol.RegisterHTTP{Subdomain: "third-name"})
	c.requireClosed(waitFor)
}

// ---- unknown message types ----

func TestUnknownMessageTypesCloseTheSessionAtTheThird(t *testing.T) {
	addr, _ := serve(t, staticOpts(), nil)
	c, _ := login(t, addr, staticToken)

	require.NoError(t, c.send("bogus-one", nil))
	require.NoError(t, c.send("bogus-two", nil))
	c.requireOpen() // two are tolerated

	c.sendEnding("bogus-three", nil)
	c.requireClosed(waitFor)
}

// Types that exist but are not for the server to receive count as well.
func TestMisdirectedMessageTypesCountAsUnknown(t *testing.T) {
	logger, logs := captureLogger()
	opts := staticOpts()
	opts.Logger = logger
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, staticToken)

	require.NoError(t, c.send(protocol.TypeHello, protocol.Hello{Token: staticToken}))
	require.NoError(t, c.send(protocol.TypePong, nil))
	c.requireOpen()
	c.sendEnding(protocol.TypeHelloAck, nil)
	c.requireClosed(waitFor)

	// The third misdirected type, and nothing else, ended the session.
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "too many unknown messages") },
		waitFor, 20*time.Millisecond, "log: %s", logs.String())
	out := logs.String()
	for _, want := range []string{"type=hello count=1", "type=pong count=2", "type=hello_ack count=3"} {
		assert.Contains(t, out, want)
	}
	assert.Equal(t, 1, strings.Count(out, "too many unknown messages"), out)
	assert.NotContains(t, out, "control message rate exceeded")
}

func TestUnknownMessageTypeIsLoggedTruncatedTo32Characters(t *testing.T) {
	logger, logs := captureLogger()
	opts := staticOpts()
	opts.Logger = logger
	addr, _ := serve(t, opts, nil)
	c, _ := login(t, addr, staticToken)

	long := strings.Repeat("0123456789", 30) // 300 characters
	require.NoError(t, c.send(protocol.MessageType(long), nil))
	c.requireOpen()

	out := logs.String()
	assert.Contains(t, out, "unknown message type")
	assert.Contains(t, out, long[:32])
	assert.NotContains(t, out, long[:33])
}

func TestWrongFirstMessageTypeIsLoggedTruncated(t *testing.T) {
	logger, logs := captureLogger()
	opts := staticOpts()
	opts.Logger = logger
	addr, _ := serve(t, opts, nil)
	c := connect(t, addr)

	long := strings.Repeat("abcdefghij", 30)
	c.sendEnding(protocol.MessageType(long), nil)
	c.requireClosed(waitFor)

	require.Eventually(t, func() bool { return strings.Contains(logs.String(), long[:32]) }, waitFor, 20*time.Millisecond)
	assert.NotContains(t, logs.String(), long[:33])
}

func TestClip(t *testing.T) {
	assert.Equal(t, "", clip("", 32))
	assert.Equal(t, "short", clip("short", 32))
	exact := strings.Repeat("x", 32)
	assert.Equal(t, exact, clip(exact, 32))
	assert.Equal(t, exact, clip(exact+"y", 32))
	// Characters, not bytes: 40 two-byte letters are cut to 32 letters.
	assert.Equal(t, strings.Repeat("ä", 32), clip(strings.Repeat("ä", 40), 32))
}

// ---- failed logins are logged ----

func TestFailedLoginIsLoggedWithRemoteAddressAndWithoutToken(t *testing.T) {
	logger, logs := captureLogger()
	opts := staticOpts()
	opts.Logger = logger
	addr, _ := serve(t, opts, nil)

	c := connect(t, addr)
	require.Equal(t, "invalid token", c.hello("twbl_TOPSECRETVALUE").Error)

	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "authentication failed") },
		waitFor, 20*time.Millisecond)
	out := logs.String()
	assert.Contains(t, out, c.conn.LocalAddr().String(), "the client's address must be in the log")
	assert.NotContains(t, out, "TOPSECRETVALUE", "the token must not be in the log")
}

// ---- recover per connection ----

type panickingUDPEdge struct{}

func (panickingUDPEdge) Open(context.Context, int, edgeudp.TunnelOpener) (int, error) {
	panic("edge exploded")
}
func (panickingUDPEdge) Close(int) {}

func TestPanicInOneConnectionDoesNotTakeTheServerDown(t *testing.T) {
	logger, logs := captureLogger()
	reg := registry.New()
	opts := staticOpts()
	opts.Logger = logger
	opts.Registry = reg
	opts.UDPEdge = panickingUDPEdge{}
	addr, _ := serve(t, opts, nil)

	c, _ := login(t, addr, staticToken)
	c.sendEnding(protocol.TypeRegisterUDP, protocol.RegisterUDP{})
	c.requireClosed(waitFor)

	// The server keeps serving and the broken session left nothing behind.
	other, _ := login(t, addr, staticToken)
	other.requireOpen()
	require.Eventually(t, func() bool { return len(reg.SnapshotAll()) == 1 }, waitFor, 20*time.Millisecond)
	assert.Contains(t, logs.String(), "edge exploded")
}

// ---- accept loop backoff ----

func TestNextAcceptDelay(t *testing.T) {
	want := []time.Duration{5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000}
	var d time.Duration
	for i, ms := range want {
		d = nextAcceptDelay(d)
		assert.Equal(t, ms*time.Millisecond, d, "step %d", i+1)
	}
}

// failingListener fails every Accept until it is closed. After block() an
// Accept call waits for Close instead, like a healthy listener without
// incoming connections.
type failingListener struct {
	calls    atomic.Int32
	blocking atomic.Bool
	closed   chan struct{}
	once     sync.Once
}

func (l *failingListener) block() { l.blocking.Store(true) }

func (l *failingListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}
	if l.blocking.Load() {
		<-l.closed
		return nil, net.ErrClosed
	}
	l.calls.Add(1)
	return nil, errors.New("accept: too many open files")
}
func (l *failingListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *failingListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestServeBacksOffWhileAcceptFails(t *testing.T) {
	ln := &failingListener{closed: make(chan struct{})}
	acc := New(staticOpts())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- acc.Serve(ctx, ln) }()

	start := time.Now()
	// Earliest time of the n-th Accept call with pauses of 5, 10, 20, ... ms
	// that stop growing at one second.
	earliest := []time.Duration{0, 5, 15, 35, 75, 155, 315, 635, 1635, 2635, 3635, 4635, 5635}
	require.Eventually(t, func() bool { return ln.calls.Load() >= 6 }, waitFor, 10*time.Millisecond,
		"the loop must keep retrying")
	calls := int(ln.calls.Load())
	elapsed := time.Since(start)
	require.Less(t, calls, len(earliest), "far too many Accept calls: %d in %s", calls, elapsed)
	// The n-th call cannot have happened before its earliest time. A loop
	// without backoff makes thousands of calls in the first 155 ms.
	assert.GreaterOrEqual(t, elapsed, earliest[calls-1]*time.Millisecond,
		"%d Accept calls after only %s", calls, elapsed)

	// Cancelling ends Serve promptly while it is waiting to retry: it must
	// not go back into Accept, which from now on would not return.
	ln.block()
	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(waitFor):
		t.Fatal("Serve did not return after the context was cancelled")
	}
	_ = ln.Close()
}

// ---- session IDs (Hinweise) ----

func TestSessionIDsAre16RandomBytes(t *testing.T) {
	addr, _ := serve(t, staticOpts(), nil)
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		_, ack := login(t, addr, staticToken)
		raw, err := hex.DecodeString(ack.SessionID)
		require.NoError(t, err)
		assert.Len(t, raw, 16)
		assert.False(t, seen[ack.SessionID], "session ID repeated")
		seen[ack.SessionID] = true
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("entropy source failed") }

func TestNewSessionIDReportsRandomSourceFailure(t *testing.T) {
	id, err := newSessionID(brokenReader{})
	require.Error(t, err)
	assert.Empty(t, id)
}

func TestLoginFailsClosedWhenTheRandomSourceFails(t *testing.T) {
	reg := registry.New()
	opts := staticOpts()
	opts.Registry = reg
	addr, _ := serve(t, opts, func(a *Acceptor) { a.random = brokenReader{} })

	c := connect(t, addr)
	ack := c.hello(staticToken)
	assert.Equal(t, "internal error", ack.Error)
	assert.Empty(t, ack.SessionID)
	c.requireClosed(waitFor)
	assert.Empty(t, reg.SnapshotAll())
}
