package integration

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/client/connector"
	"github.com/Bazinga0o0/tunnel/internal/client/dialer"
	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

// TestTCPTunnelFlow exercises the full RegisterTCP path end-to-end: real DB
// token auth -> acceptor allocates a pool port -> a public TCP dial is
// forwarded over yamux to a client-side connector -> the connector forwards
// to a fake local echo service. After the session closes, the registry
// entry is cleaned up.
func TestTCPTunnelFlow(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	u, err := userSvc.Create(ctx, "tcp@example.com", "pw12345678")
	require.NoError(t, err)

	tokenSvc := tokens.NewService(pool)
	raw, _, err := tokenSvc.Issue(ctx, u.ID, "tcp-laptop")
	require.NoError(t, err)

	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	reg := registry.New()
	// A free range found at run time: fixed numbers can fall into the port
	// ranges Windows reserves.
	portLow, portHigh := testports.FreeTCPRange(t, 11)
	tcpPool := edgetcp.NewPool(portLow, portHigh)
	tcpMgr := edgetcp.NewWithOptions(edgetcp.Options{Pool: tcpPool, BindHost: testports.Loopback})

	tunLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	defer tunLn.Close()

	acc := acceptor.New(acceptor.Options{
		Domain:     "localhost",
		Registry:   reg,
		DBVerifier: auth.NewDBVerifier(tokenSvc),
		TCPEdge:    tcpMgr,
	})
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go acc.Serve(serveCtx, tunLn)

	// Fake local service: an echo server the client-side connector forwards to.
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer localLn.Close()
	go func() {
		for {
			conn, err := localLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// Client: dial acceptor, register a TCP tunnel, forward streams via the
	// real connector (same code path the CLI uses).
	d := dialer.New(dialer.Options{
		ServerAddr:         tunLn.Addr().String(),
		Token:              raw,
		InsecureSkipVerify: true,
	})
	sess, err := d.Dial(ctx)
	require.NoError(t, err)
	defer sess.Close()

	ack, err := sess.RegisterTCP(ctx, 0)
	require.NoError(t, err)
	require.GreaterOrEqual(t, ack.Port, portLow)
	require.LessOrEqual(t, ack.Port, portHigh)

	conn := connector.New(connector.Options{LocalAddr: localLn.Addr().String(), ExpectedType: "tcp"})
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			stream, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go func() { _ = conn.Handle(stream) }()
		}
	}()

	// Wait until the registry has the TCP tunnel wired up.
	require.Eventually(t, func() bool {
		_, ok := reg.LookupTCP(ack.Port)
		return ok
	}, 2*time.Second, 20*time.Millisecond)

	// Public-side: dial the allocated port, send "ping", expect the echo
	// server to bounce it back.
	publicConn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(ack.Port), 2*time.Second)
	require.NoError(t, err)
	defer publicConn.Close()

	_, err = publicConn.Write([]byte("ping"))
	require.NoError(t, err)

	buf := make([]byte, 4)
	_ = publicConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadFull(publicConn, buf)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, "ping", string(buf))

	// After session close, the public port should be released from the registry.
	_ = sess.Close()
	require.Eventually(t, func() bool {
		_, ok := reg.LookupTCP(ack.Port)
		return !ok
	}, 2*time.Second, 50*time.Millisecond)

	// The AcceptStream goroutine must have exited after sess.Close().
	select {
	case <-acceptDone:
	case <-time.After(2 * time.Second):
		t.Fatal("accept goroutine did not exit after session close")
	}
}

// TestTCPTunnelReservedPortFlow covers the port reservation rule end to end
// with the real TCP edge: in database mode a client gets a specific port only
// if that port is reserved for its user. A refused request opens no listener;
// the owner's tunnel forwards traffic; the listener goes away with the
// session.
func TestTCPTunnelReservedPortFlow(t *testing.T) {
	pool := dbtest.Pool(t)
	defer pool.Close()
	ctx := context.Background()

	userSvc := users.NewService(pool)
	owner, err := userSvc.Create(ctx, "port-owner@example.com", "pw12345678")
	require.NoError(t, err)
	other, err := userSvc.Create(ctx, "port-other@example.com", "pw12345678")
	require.NoError(t, err)

	tokenSvc := tokens.NewService(pool)
	ownerRaw, _, err := tokenSvc.Issue(ctx, owner.ID, "owner-laptop")
	require.NoError(t, err)
	otherRaw, _, err := tokenSvc.Issue(ctx, other.ID, "other-laptop")
	require.NoError(t, err)

	// A range of its own, found at run time, so that this test does not meet
	// the listeners of other tests or a port range Windows reserves.
	portLow, portHigh := testports.FreeTCPRange(t, 11)
	reservedPort, freePort := portLow+5, portLow+6
	resSvc := reservations.NewService(pool)
	require.NoError(t, resSvc.GrantTCPPort(ctx, reservedPort, owner.ID))

	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	reg := registry.New()
	tcpMgr := edgetcp.NewWithOptions(edgetcp.Options{Pool: edgetcp.NewPool(portLow, portHigh), BindHost: testports.Loopback})

	tunLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	defer tunLn.Close()

	acc := acceptor.New(acceptor.Options{
		Domain:       "localhost",
		Registry:     reg,
		DBVerifier:   auth.NewDBVerifier(tokenSvc),
		Reservations: resSvc,
		TCPEdge:      tcpMgr,
	})
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go acc.Serve(serveCtx, tunLn)

	dial := func(token string) *dialer.Session {
		sess, err := dialer.New(dialer.Options{
			ServerAddr:         tunLn.Addr().String(),
			Token:              token,
			InsecureSkipVerify: true,
		}).Dial(ctx)
		require.NoError(t, err)
		return sess
	}
	listening := func(port int) bool {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}

	// The other user gets neither the port that is reserved for the owner
	// nor a port that is not reserved at all.
	otherSess := dial(otherRaw)
	defer otherSess.Close()
	_, err = otherSess.RegisterTCP(ctx, reservedPort)
	require.EqualError(t, err, "port reserved")
	_, err = otherSess.RegisterTCP(ctx, freePort)
	require.EqualError(t, err, "port not reserved")
	require.False(t, listening(reservedPort), "a refused request must not open a listener")
	require.False(t, listening(freePort), "a refused request must not open a listener")
	_, ok := reg.LookupTCP(reservedPort)
	require.False(t, ok)
	_, ok = reg.LookupTCP(freePort)
	require.False(t, ok)

	// The owner gets the reserved port and it forwards.
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer localLn.Close()
	go func() {
		for {
			conn, err := localLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	ownerSess := dial(ownerRaw)
	defer ownerSess.Close()
	ack, err := ownerSess.RegisterTCP(ctx, reservedPort)
	require.NoError(t, err)
	require.Equal(t, reservedPort, ack.Port)

	conn := connector.New(connector.Options{LocalAddr: localLn.Addr().String(), ExpectedType: "tcp"})
	go func() {
		for {
			stream, err := ownerSess.AcceptStream()
			if err != nil {
				return
			}
			go func() { _ = conn.Handle(stream) }()
		}
	}()

	// The waits below end as soon as the event happens; they are long so
	// that a loaded machine does not fail the test.
	publicConn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(reservedPort), 15*time.Second)
	require.NoError(t, err)
	defer publicConn.Close()
	_, err = publicConn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_ = publicConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, err = io.ReadFull(publicConn, buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf))

	// With the session the registration and the listener go away.
	_ = ownerSess.Close()
	require.Eventually(t, func() bool {
		_, ok := reg.LookupTCP(reservedPort)
		return !ok && !listening(reservedPort)
	}, 15*time.Second, 50*time.Millisecond)
}
