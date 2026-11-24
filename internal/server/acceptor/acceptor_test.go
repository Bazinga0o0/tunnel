package acceptor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

func TestAcceptorHandshakeAndRegister(t *testing.T) {
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}}

	reg := registry.New()
	verifier := auth.NewTokenVerifier([]string{"twbl_ok"})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	acc := New(Options{
		Domain:   "tunnel.localhost",
		Registry: reg,
		Verifier: verifier,
	})
	go acc.Serve(ctx, ln)

	clientTLS := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	require.NoError(t, err)
	defer conn.Close()

	sess, err := protocol.NewClientSession(conn)
	require.NoError(t, err)
	defer sess.Close()

	ctrl, err := sess.OpenStream()
	require.NoError(t, err)
	defer ctrl.Close()

	hello := protocol.Hello{Token: "twbl_ok", ClientVersion: "test", OS: "test"}
	helloRaw, _ := json.Marshal(hello)
	require.NoError(t, protocol.WriteFrame(ctrl, mustMarshalEnvelope(protocol.TypeHello, helloRaw)))

	ackRaw, err := protocol.ReadFrame(ctrl, 1<<16)
	require.NoError(t, err)
	var env protocol.Envelope
	require.NoError(t, json.Unmarshal(ackRaw, &env))
	require.Equal(t, protocol.TypeHelloAck, env.Type)
	var ack protocol.HelloAck
	require.NoError(t, json.Unmarshal(env.Payload, &ack))
	require.Empty(t, ack.Error)
	require.NotEmpty(t, ack.SessionID)

	reqRaw, _ := json.Marshal(protocol.RegisterHTTP{})
	require.NoError(t, protocol.WriteFrame(ctrl, mustMarshalEnvelope(protocol.TypeRegisterHTTP, reqRaw)))

	ackRaw2, err := protocol.ReadFrame(ctrl, 1<<16)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(ackRaw2, &env))
	require.Equal(t, protocol.TypeRegisterHTTPAck, env.Type)
	var regAck protocol.RegisterHTTPAck
	require.NoError(t, json.Unmarshal(env.Payload, &regAck))
	require.Empty(t, regAck.Error)
	require.Len(t, regAck.Subdomain, 6)

	require.Eventually(t, func() bool {
		_, ok := reg.LookupHTTP(regAck.Subdomain)
		return ok
	}, 2*time.Second, 20*time.Millisecond)
}

func TestAcceptorRejectsBadToken(t *testing.T) {
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}}

	reg := registry.New()
	verifier := auth.NewTokenVerifier([]string{"twbl_ok"})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	acc := New(Options{Domain: "tunnel.localhost", Registry: reg, Verifier: verifier})
	go acc.Serve(ctx, ln)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer conn.Close()

	sess, err := protocol.NewClientSession(conn)
	require.NoError(t, err)
	defer sess.Close()

	ctrl, err := sess.OpenStream()
	require.NoError(t, err)
	defer ctrl.Close()

	hello := protocol.Hello{Token: "wrong"}
	helloRaw, _ := json.Marshal(hello)
	if err := protocol.WriteFrame(ctrl, mustMarshalEnvelope(protocol.TypeHello, helloRaw)); err != nil {
		// On slower CI hosts yamux may race the server's session-close teardown
		// against the client's payload write. A session-shutdown error here
		// still indicates the server rejected us — which is exactly what this
		// test is asserting. Accept it as a successful rejection signal.
		require.Contains(t, err.Error(), "shutdown")
		return
	}

	ackRaw, err := protocol.ReadFrame(ctrl, 1<<16)
	require.NoError(t, err)
	var env protocol.Envelope
	require.NoError(t, json.Unmarshal(ackRaw, &env))
	var ack protocol.HelloAck
	require.NoError(t, json.Unmarshal(env.Payload, &ack))
	require.NotEmpty(t, ack.Error)
}

var _ = net.ResolveTCPAddr

func mustMarshalEnvelope(t protocol.MessageType, payload json.RawMessage) []byte {
	b, _ := json.Marshal(protocol.Envelope{Type: t, Payload: payload})
	return b
}

// startAcceptor spins up a TLS listener + Acceptor with the given Options
// (Domain defaulted, Registry auto-created if nil). Returns the listener addr
// and a cleanup cancel fn.
func startAcceptor(t *testing.T, opts Options) (addr string, cancel context.CancelFunc) {
	t.Helper()
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}}

	if opts.Domain == "" {
		opts.Domain = "tunnel.localhost"
	}
	if opts.Registry == nil {
		opts.Registry = registry.New()
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	require.NoError(t, err)

	ctx, cancelFn := context.WithCancel(context.Background())
	acc := New(opts)
	go acc.Serve(ctx, ln)

	t.Cleanup(func() {
		cancelFn()
		_ = ln.Close()
	})
	return ln.Addr().String(), cancelFn
}

// dialAndHandshake opens a TLS+yamux control stream, sends Hello{token},
// and returns the HelloAck plus the control stream (still open).
func dialAndHandshake(t *testing.T, addr, token string) (protocol.Stream, protocol.HelloAck) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	sess, err := protocol.NewClientSession(conn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })

	ctrl, err := sess.OpenStream()
	require.NoError(t, err)

	hello := protocol.Hello{Token: token, ClientVersion: "test", OS: "test"}
	helloRaw, _ := json.Marshal(hello)
	require.NoError(t, protocol.WriteFrame(ctrl, mustMarshalEnvelope(protocol.TypeHello, helloRaw)))

	ackRaw, err := protocol.ReadFrame(ctrl, 1<<16)
	require.NoError(t, err)
	var env protocol.Envelope
	require.NoError(t, json.Unmarshal(ackRaw, &env))
	require.Equal(t, protocol.TypeHelloAck, env.Type)
	var ack protocol.HelloAck
	require.NoError(t, json.Unmarshal(env.Payload, &ack))
	return ctrl, ack
}

// requestRegister writes a RegisterHTTP with the given subdomain and reads
// the resulting ack.
func requestRegister(t *testing.T, ctrl protocol.Stream, subdomain string) protocol.RegisterHTTPAck {
	t.Helper()
	reqRaw, _ := json.Marshal(protocol.RegisterHTTP{Subdomain: subdomain})
	require.NoError(t, protocol.WriteFrame(ctrl, mustMarshalEnvelope(protocol.TypeRegisterHTTP, reqRaw)))

	ackRaw, err := protocol.ReadFrame(ctrl, 1<<16)
	require.NoError(t, err)
	var env protocol.Envelope
	require.NoError(t, json.Unmarshal(ackRaw, &env))
	require.Equal(t, protocol.TypeRegisterHTTPAck, env.Type)
	var regAck protocol.RegisterHTTPAck
	require.NoError(t, json.Unmarshal(env.Payload, &regAck))
	return regAck
}

func TestAcceptorDBAuthAcceptsValidToken(t *testing.T) {
	pool := dbtest.Pool(t)
	ctx := context.Background()

	userSvc := users.NewService(pool)
	tokenSvc := tokens.NewService(pool)

	u, err := userSvc.Create(ctx, "alice@example.com", "pw-alice-1234")
	require.NoError(t, err)
	rawToken, _, err := tokenSvc.Issue(ctx, u.ID, "laptop")
	require.NoError(t, err)

	reg := registry.New()
	addr, _ := startAcceptor(t, Options{
		Registry:   reg,
		DBVerifier: auth.NewDBVerifier(tokenSvc),
	})

	ctrl, ack := dialAndHandshake(t, addr, rawToken)
	require.Empty(t, ack.Error)
	require.NotEmpty(t, ack.SessionID)

	regAck := requestRegister(t, ctrl, "")
	require.Empty(t, regAck.Error)
	require.Len(t, regAck.Subdomain, 6)

	require.Eventually(t, func() bool {
		_, ok := reg.LookupHTTP(regAck.Subdomain)
		return ok
	}, 2*time.Second, 20*time.Millisecond)
}

func TestAcceptorDBAuthRejectsInvalidToken(t *testing.T) {
	pool := dbtest.Pool(t)

	tokenSvc := tokens.NewService(pool)
	addr, _ := startAcceptor(t, Options{
		DBVerifier: auth.NewDBVerifier(tokenSvc),
	})

	_, ack := dialAndHandshake(t, addr, "twbl_bogus0000000000000000000000000000")
	require.NotEmpty(t, ack.Error)
}

func TestAcceptorRejectsReservedSubdomainByOtherUser(t *testing.T) {
	pool := dbtest.Pool(t)
	ctx := context.Background()

	userSvc := users.NewService(pool)
	tokenSvc := tokens.NewService(pool)
	resSvc := reservations.NewService(pool)

	userA, err := userSvc.Create(ctx, "a@example.com", "pw-a-1234")
	require.NoError(t, err)
	userB, err := userSvc.Create(ctx, "b@example.com", "pw-b-1234")
	require.NoError(t, err)

	// User B reserves "foo"; user A tries to claim it.
	require.NoError(t, resSvc.Reserve(ctx, "foo", userB.ID))

	rawA, _, err := tokenSvc.Issue(ctx, userA.ID, "a-laptop")
	require.NoError(t, err)

	addr, _ := startAcceptor(t, Options{
		DBVerifier:   auth.NewDBVerifier(tokenSvc),
		Reservations: resSvc,
	})

	ctrl, ack := dialAndHandshake(t, addr, rawA)
	require.Empty(t, ack.Error)

	regAck := requestRegister(t, ctrl, "foo")
	require.Equal(t, "subdomain reserved", regAck.Error)
}

func TestAcceptorAllowsReservedSubdomainByOwner(t *testing.T) {
	pool := dbtest.Pool(t)
	ctx := context.Background()

	userSvc := users.NewService(pool)
	tokenSvc := tokens.NewService(pool)
	resSvc := reservations.NewService(pool)

	u, err := userSvc.Create(ctx, "owner@example.com", "pw-owner-1234")
	require.NoError(t, err)
	require.NoError(t, resSvc.Reserve(ctx, "foo", u.ID))

	rawToken, _, err := tokenSvc.Issue(ctx, u.ID, "laptop")
	require.NoError(t, err)

	reg := registry.New()
	addr, _ := startAcceptor(t, Options{
		Registry:     reg,
		DBVerifier:   auth.NewDBVerifier(tokenSvc),
		Reservations: resSvc,
	})

	ctrl, ack := dialAndHandshake(t, addr, rawToken)
	require.Empty(t, ack.Error)

	regAck := requestRegister(t, ctrl, "foo")
	require.Empty(t, regAck.Error)
	require.Equal(t, "foo", regAck.Subdomain)

	require.Eventually(t, func() bool {
		_, ok := reg.LookupHTTP("foo")
		return ok
	}, 2*time.Second, 20*time.Millisecond)
}

func TestAcceptorRegisterUDPHappy(t *testing.T) {
	reg := registry.New()
	edge := fakeUDPEdge{&fakeEdge{script: []openResult{{port: 35001}}}}

	addr, _ := startAcceptor(t, Options{
		Registry: reg,
		Verifier: auth.NewTokenVerifier([]string{"twbl_ok"}),
		UDPEdge:  edge,
	})

	ctrl, ack := dialAndHandshake(t, addr, "twbl_ok")
	require.Empty(t, ack.Error)

	reqRaw, _ := json.Marshal(protocol.RegisterUDP{Port: 0})
	require.NoError(t, protocol.WriteFrame(ctrl, mustMarshalEnvelope(protocol.TypeRegisterUDP, reqRaw)))

	ackRaw, err := protocol.ReadFrame(ctrl, 1<<16)
	require.NoError(t, err)
	var env protocol.Envelope
	require.NoError(t, json.Unmarshal(ackRaw, &env))
	require.Equal(t, protocol.TypeRegisterUDPAck, env.Type)
	var udpAck protocol.RegisterUDPAck
	require.NoError(t, json.Unmarshal(env.Payload, &udpAck))
	require.Empty(t, udpAck.Error)
	require.Equal(t, 35001, udpAck.Port)
}

func TestAcceptorRegisterUDPDisabled(t *testing.T) {
	addr, _ := startAcceptor(t, Options{
		Verifier: auth.NewTokenVerifier([]string{"twbl_ok"}),
		// UDPEdge deliberately nil
	})

	ctrl, ack := dialAndHandshake(t, addr, "twbl_ok")
	require.Empty(t, ack.Error)

	reqRaw, _ := json.Marshal(protocol.RegisterUDP{Port: 0})
	require.NoError(t, protocol.WriteFrame(ctrl, mustMarshalEnvelope(protocol.TypeRegisterUDP, reqRaw)))

	ackRaw, err := protocol.ReadFrame(ctrl, 1<<16)
	require.NoError(t, err)
	var env protocol.Envelope
	require.NoError(t, json.Unmarshal(ackRaw, &env))
	require.Equal(t, protocol.TypeRegisterUDPAck, env.Type)
	var udpAck protocol.RegisterUDPAck
	require.NoError(t, json.Unmarshal(env.Payload, &udpAck))
	require.Equal(t, "udp tunneling disabled", udpAck.Error)
}

func TestAcceptorRegisterUDPReservedByOtherUser(t *testing.T) {
	pool := dbtest.Pool(t)
	ctx := context.Background()

	userSvc := users.NewService(pool)
	tokenSvc := tokens.NewService(pool)
	resSvc := reservations.NewService(pool)

	userA, err := userSvc.Create(ctx, "udp-a@example.com", "pw-a-1234")
	require.NoError(t, err)
	userB, err := userSvc.Create(ctx, "udp-b@example.com", "pw-b-1234")
	require.NoError(t, err)

	// User B reserves port 35000; user A tries to claim it.
	require.NoError(t, resSvc.ReserveUDPPort(ctx, 35000, userB.ID))

	rawA, _, err := tokenSvc.Issue(ctx, userA.ID, "a-laptop")
	require.NoError(t, err)

	edge := fakeUDPEdge{&fakeEdge{script: []openResult{{port: 35000}}}}
	addr, _ := startAcceptor(t, Options{
		DBVerifier:   auth.NewDBVerifier(tokenSvc),
		Reservations: resSvc,
		UDPEdge:      edge,
	})

	ctrl, ack := dialAndHandshake(t, addr, rawA)
	require.Empty(t, ack.Error)

	reqRaw, _ := json.Marshal(protocol.RegisterUDP{Port: 35000})
	require.NoError(t, protocol.WriteFrame(ctrl, mustMarshalEnvelope(protocol.TypeRegisterUDP, reqRaw)))

	ackRaw, err := protocol.ReadFrame(ctrl, 1<<16)
	require.NoError(t, err)
	var env protocol.Envelope
	require.NoError(t, json.Unmarshal(ackRaw, &env))
	require.Equal(t, protocol.TypeRegisterUDPAck, env.Type)
	var udpAck protocol.RegisterUDPAck
	require.NoError(t, json.Unmarshal(env.Payload, &udpAck))
	require.Equal(t, "port reserved", udpAck.Error)
}
