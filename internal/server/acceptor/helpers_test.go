package acceptor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeudp"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

const staticToken = "twbl_ok"

// waitFor is how long a test waits for the server to do something it is
// expected to do. The wait ends as soon as it happens, so the generous value
// costs nothing in a passing run and keeps a loaded machine from failing it.
const waitFor = 15 * time.Second

// staticOpts returns Options for static-token mode with the token above.
func staticOpts() Options {
	return Options{Verifier: auth.NewTokenVerifier([]string{staticToken})}
}

// lockedBuffer is a goroutine-safe log sink.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func captureLogger() (*slog.Logger, *lockedBuffer) {
	buf := &lockedBuffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

// serve starts an Acceptor on a fresh TLS listener. tweak, when not nil, may
// replace the acceptor's seams before the first connection is accepted.
func serve(t *testing.T, opts Options, tweak func(*Acceptor)) (addr string, acc *Acceptor) {
	t.Helper()
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	if opts.Domain == "" {
		opts.Domain = "tunnel.localhost"
	}
	if opts.Registry == nil {
		opts.Registry = registry.New()
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	acc = New(opts)
	if tweak != nil {
		tweak(acc)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = acc.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String(), acc
}

// client is the test's end of one tunnel connection.
type client struct {
	t    *testing.T
	conn net.Conn
	sess protocol.Session
	ctrl protocol.Stream
}

// dialRaw opens a plain TCP connection and sends nothing.
func dialRaw(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// connect does the TLS handshake, starts yamux and opens the control stream.
// It does not send a hello.
func connect(t *testing.T, addr string) *client {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	sess, err := protocol.NewClientSession(conn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	ctrl, err := sess.OpenStream()
	require.NoError(t, err)
	return &client{t: t, conn: conn, sess: sess, ctrl: ctrl}
}

func envelope(typ protocol.MessageType, payload any) []byte {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			panic(err)
		}
		raw = b
	}
	b, err := json.Marshal(protocol.Envelope{Type: typ, Payload: raw})
	if err != nil {
		panic(err)
	}
	return b
}

// send writes one control message and returns the write error.
func (c *client) send(typ protocol.MessageType, payload any) error {
	return protocol.WriteFrame(c.ctrl, envelope(typ, payload))
}

// A write or open that makes the server end the session may fail with the
// session's end although its frame went out. yamux's Write and OpenStream
// hand the frame to the send loop and then wait for the loop to report it
// written or for the session to end, whichever they see first. On loopback
// the server can read the frame and close the connection, and the client's
// receive loop can see the close, before the waiting call picks up the
// report: it then returns ErrSessionShutdown. Such a call says nothing about
// the server, so the tests prove what the server did by its effects (the
// closed session, its log lines, its counters, the registry).

// requireSentOrShutdown fails the test unless err is nil or the session's end.
func requireSentOrShutdown(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		require.ErrorIs(t, err, yamux.ErrSessionShutdown)
	}
}

// sendEnding writes a control message after which the server is expected to
// end the session.
func (c *client) sendEnding(typ protocol.MessageType, payload any) {
	c.t.Helper()
	requireSentOrShutdown(c.t, c.send(typ, payload))
}

// writeFrameEnding writes a raw frame after which the server is expected to
// end the session.
func (c *client) writeFrameEnding(frame []byte) {
	c.t.Helper()
	requireSentOrShutdown(c.t, protocol.WriteFrame(c.ctrl, frame))
}

// openEnding opens a stream after which the server is expected to end the
// session.
func (c *client) openEnding() {
	c.t.Helper()
	_, err := c.sess.OpenStream()
	requireSentOrShutdown(c.t, err)
}

// isTimeout reports whether err is a read deadline that ran out, as opposed
// to the connection having ended.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// recv reads one control message, waiting at most the given time.
func (c *client) recv(within time.Duration) (protocol.Envelope, error) {
	var env protocol.Envelope
	d, ok := c.ctrl.(interface{ SetReadDeadline(time.Time) error })
	require.True(c.t, ok)
	require.NoError(c.t, d.SetReadDeadline(time.Now().Add(within)))
	raw, err := protocol.ReadFrame(c.ctrl, 1<<20)
	if err != nil {
		return env, err
	}
	require.NoError(c.t, json.Unmarshal(raw, &env))
	return env, nil
}

// mustRecv reads one control message of the expected type into out.
func (c *client) mustRecv(want protocol.MessageType, out any) {
	c.t.Helper()
	env, err := c.recv(waitFor)
	require.NoError(c.t, err)
	require.Equal(c.t, want, env.Type)
	if out != nil {
		require.NoError(c.t, json.Unmarshal(env.Payload, out))
	}
}

// hello sends the hello message and returns the server's answer. A refused
// login ends the session right after the answer, so the send may report the
// session's end; the answer read below proves that the hello arrived.
func (c *client) hello(token string) protocol.HelloAck {
	c.t.Helper()
	requireSentOrShutdown(c.t, c.send(protocol.TypeHello, protocol.Hello{Token: token, ClientVersion: "test", OS: "test"}))
	var ack protocol.HelloAck
	c.mustRecv(protocol.TypeHelloAck, &ack)
	return ack
}

// login connects and authenticates; the handshake must succeed.
func login(t *testing.T, addr, token string) (*client, protocol.HelloAck) {
	t.Helper()
	c := connect(t, addr)
	ack := c.hello(token)
	require.Empty(t, ack.Error)
	require.NotEmpty(t, ack.SessionID)
	return c, ack
}

func (c *client) registerHTTP(subdomain string) protocol.RegisterHTTPAck {
	c.t.Helper()
	require.NoError(c.t, c.send(protocol.TypeRegisterHTTP, protocol.RegisterHTTP{Subdomain: subdomain}))
	var ack protocol.RegisterHTTPAck
	c.mustRecv(protocol.TypeRegisterHTTPAck, &ack)
	return ack
}

// registerTCP sends the raw JSON port so that values outside the int range
// of the message struct can be sent too.
func (c *client) registerTCP(port int64) protocol.RegisterTCPAck {
	c.t.Helper()
	require.NoError(c.t, c.send(protocol.TypeRegisterTCP, map[string]int64{"port": port}))
	var ack protocol.RegisterTCPAck
	c.mustRecv(protocol.TypeRegisterTCPAck, &ack)
	return ack
}

func (c *client) registerUDP(port int64) protocol.RegisterUDPAck {
	c.t.Helper()
	require.NoError(c.t, c.send(protocol.TypeRegisterUDP, map[string]int64{"port": port}))
	var ack protocol.RegisterUDPAck
	c.mustRecv(protocol.TypeRegisterUDPAck, &ack)
	return ack
}

// requireOpen proves the session is alive: a ping is answered.
func (c *client) requireOpen() {
	c.t.Helper()
	require.NoError(c.t, c.send(protocol.TypePing, nil))
	c.mustRecv(protocol.TypePong, nil)
}

// requireClosed proves the server ended the session: reading the control
// stream fails with something other than "nothing arrived yet".
func (c *client) requireClosed(within time.Duration) {
	c.t.Helper()
	env, err := c.recv(within)
	require.Error(c.t, err, "expected the session to be closed, got message %q", env.Type)
	require.False(c.t, isTimeout(err), "session is still open after %s", within)
}

// requireConnClosed proves the server closed a raw connection.
func requireConnClosed(t *testing.T, conn net.Conn, within time.Duration) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(within)))
	_, err := conn.Read(make([]byte, 1))
	require.Error(t, err)
	require.False(t, isTimeout(err), "connection is still open after %s", within)
}

// requireConnOpen proves a raw connection is not closed yet: a short read
// runs into its deadline.
func requireConnOpen(t *testing.T, conn net.Conn, wait time.Duration) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(wait)))
	_, err := conn.Read(make([]byte, 1))
	require.Error(t, err)
	require.True(t, isTimeout(err), "connection was closed: %v", err)
}

// ---- fake edges ----

type openResult struct {
	port int
	err  error
}

// fakeEdge records Open and Close calls. Open answers from script; once the
// script is used up it returns the preferred port, or ports counted up from
// 40000 for preferred == 0.
type fakeEdge struct {
	mu      sync.Mutex
	script  []openResult
	opens   []int // the preferred argument of every Open call
	closes  []int // the port argument of every Close call
	next    int
	onOpen  func(preferred int)
	onClose func(port int)
}

func (f *fakeEdge) open(preferred int) (int, error) {
	f.mu.Lock()
	f.opens = append(f.opens, preferred)
	hook := f.onOpen
	var res openResult
	switch {
	case len(f.script) > 0:
		res = f.script[0]
		f.script = f.script[1:]
	case preferred != 0:
		res = openResult{port: preferred}
	default:
		res = openResult{port: 40000 + f.next}
		f.next++
	}
	f.mu.Unlock()
	if hook != nil {
		hook(preferred)
	}
	return res.port, res.err
}

func (f *fakeEdge) Close(port int) {
	f.mu.Lock()
	f.closes = append(f.closes, port)
	hook := f.onClose
	f.mu.Unlock()
	if hook != nil {
		hook(port)
	}
}

func (f *fakeEdge) opened() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.opens...)
}

func (f *fakeEdge) closed() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.closes...)
}

type fakeTCPEdge struct{ *fakeEdge }

func (f fakeTCPEdge) Open(_ context.Context, preferred int, _ edgetcp.TunnelOpener) (int, error) {
	return f.open(preferred)
}

type fakeUDPEdge struct{ *fakeEdge }

func (f fakeUDPEdge) Open(_ context.Context, preferred int, _ edgeudp.TunnelOpener) (int, error) {
	return f.open(preferred)
}

// ---- fake reservation lookup ----

// fakeLookup answers reservation lookups from a function and counts them.
// kind is "http", "tcp" or "udp"; call counts the lookups of that kind from 1.
type fakeLookup struct {
	mu     sync.Mutex
	calls  map[string]int
	answer func(kind string, call int) (owner int64, reserved bool, err error)
}

func (f *fakeLookup) lookup(kind string) (int64, bool, error) {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[kind]++
	n := f.calls[kind]
	answer := f.answer
	f.mu.Unlock()
	return answer(kind, n)
}

func (f *fakeLookup) count(kind string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[kind]
}

func (f *fakeLookup) Owner(context.Context, string) (int64, bool, error) { return f.lookup("http") }
func (f *fakeLookup) OwnerTCPPort(context.Context, int) (int64, bool, error) {
	return f.lookup("tcp")
}
func (f *fakeLookup) OwnerUDPPort(context.Context, int) (int64, bool, error) {
	return f.lookup("udp")
}

// nameLookup answers subdomain lookups from a table of owners; no port is
// reserved. afterCheck, when set, runs after each subdomain lookup with the
// name and the number of lookups of that name so far.
type nameLookup struct {
	mu         sync.Mutex
	owners     map[string]int64
	calls      map[string]int
	afterCheck func(name string, calls int)
}

func (n *nameLookup) set(name string, owner int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.owners[name] = owner
}

func (n *nameLookup) Owner(_ context.Context, name string) (int64, bool, error) {
	n.mu.Lock()
	if n.calls == nil {
		n.calls = map[string]int{}
	}
	n.calls[name]++
	calls := n.calls[name]
	owner, ok := n.owners[name]
	hook := n.afterCheck
	n.mu.Unlock()
	if hook != nil {
		hook(name, calls)
	}
	return owner, ok, nil
}

func (n *nameLookup) OwnerTCPPort(context.Context, int) (int64, bool, error) { return 0, false, nil }
func (n *nameLookup) OwnerUDPPort(context.Context, int) (int64, bool, error) { return 0, false, nil }

// ---- database fixture ----

// dbURL returns the test database URL; newDBFixture has already skipped the
// test when it is not set.
func dbURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("TUNNELD_TEST_DATABASE_URL")
	require.NotEmpty(t, url)
	return url
}

type dbFixture struct {
	users  *users.Service
	tokens *tokens.Service
	res    *reservations.Service
}

func newDBFixture(t *testing.T) *dbFixture {
	t.Helper()
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	return &dbFixture{
		users:  users.NewService(pool),
		tokens: tokens.NewService(pool),
		res:    reservations.NewService(pool),
	}
}

// user creates an account with one API token.
func (f *dbFixture) user(t *testing.T, email string) (userID int64, rawToken string) {
	t.Helper()
	ctx := context.Background()
	u, err := f.users.Create(ctx, email, "pw-12345678")
	require.NoError(t, err)
	raw, _, err := f.tokens.Issue(ctx, u.ID, "laptop")
	require.NoError(t, err)
	return u.ID, raw
}

// dbOpts returns Options for database mode with reservations.
func (f *dbFixture) dbOpts() Options {
	return Options{DBVerifier: auth.NewDBVerifier(f.tokens), Reservations: f.res}
}
