package dialer

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeudp"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

func TestDialerConnectAndRegister(t *testing.T) {
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}}

	reg := registry.New()
	verifier := auth.NewTokenVerifier([]string{"twbl_good"})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	acc := acceptor.New(acceptor.Options{
		Domain:   "localhost",
		Registry: reg,
		Verifier: verifier,
	})
	go acc.Serve(ctx, ln)

	d := New(Options{
		ServerAddr:         ln.Addr().String(),
		Token:              "twbl_good",
		InsecureSkipVerify: true,
	})
	sess, err := d.Dial(ctx)
	require.NoError(t, err)
	defer sess.Close()

	ack, err := sess.RegisterHTTP(ctx, "")
	require.NoError(t, err)
	require.Empty(t, ack.Error)
	require.Len(t, ack.Subdomain, 6)

	require.Eventually(t, func() bool {
		_, ok := reg.LookupHTTP(ack.Subdomain)
		return ok
	}, 2*time.Second, 20*time.Millisecond)
}

func TestDialerRegisterTCP(t *testing.T) {
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}}

	reg := registry.New()
	verifier := auth.NewTokenVerifier([]string{"twbl_tcp"})

	// A free range found at run time: fixed numbers can fall into the port
	// ranges Windows reserves.
	portLow, portHigh := testports.FreeTCPRange(t, 11)
	pool := edgetcp.NewPool(portLow, portHigh)
	// Loopback only: a listener on all interfaces makes the Windows firewall
	// ask for permission on every test run.
	tcpMgr := edgetcp.NewWithOptions(edgetcp.Options{Pool: pool, BindHost: testports.Loopback})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	acc := acceptor.New(acceptor.Options{
		Domain:   "localhost",
		Registry: reg,
		Verifier: verifier,
		TCPEdge:  tcpMgr,
	})
	go acc.Serve(ctx, ln)

	d := New(Options{
		ServerAddr:         ln.Addr().String(),
		Token:              "twbl_tcp",
		InsecureSkipVerify: true,
	})
	sess, err := d.Dial(ctx)
	require.NoError(t, err)
	defer sess.Close()

	ack, err := sess.RegisterTCP(ctx, 0)
	require.NoError(t, err)
	require.Empty(t, ack.Error)
	assert.GreaterOrEqual(t, ack.Port, portLow)
	assert.LessOrEqual(t, ack.Port, portHigh)
	assert.Equal(t, fmt.Sprintf("localhost:%d", ack.Port), ack.PublicAddr)

	// Registry has the port.
	require.Eventually(t, func() bool {
		_, ok := reg.LookupTCP(ack.Port)
		return ok
	}, 2*time.Second, 20*time.Millisecond)
}

func TestDialerRegisterUDP(t *testing.T) {
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}}

	reg := registry.New()
	verifier := auth.NewTokenVerifier([]string{"twbl_udp"})

	udpLow, udpHigh := testports.FreeUDPRange(t, 11)
	pool := edgeudp.NewPool(udpLow, udpHigh)
	udpMgr := edgeudp.New(edgeudp.Options{Pool: pool, BindHost: testports.Loopback})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	acc := acceptor.New(acceptor.Options{
		Domain:   "localhost",
		Registry: reg,
		Verifier: verifier,
		UDPEdge:  udpMgr,
	})
	go acc.Serve(ctx, ln)

	d := New(Options{
		ServerAddr:         ln.Addr().String(),
		Token:              "twbl_udp",
		InsecureSkipVerify: true,
	})
	sess, err := d.Dial(ctx)
	require.NoError(t, err)
	defer sess.Close()

	ack, err := sess.RegisterUDP(ctx, 0)
	require.NoError(t, err)
	require.Empty(t, ack.Error)
	assert.GreaterOrEqual(t, ack.Port, udpLow)
	assert.LessOrEqual(t, ack.Port, udpHigh)
	assert.Equal(t, fmt.Sprintf("localhost:%d", ack.Port), ack.PublicAddr)

	// Registry has the port.
	require.Eventually(t, func() bool {
		_, ok := reg.LookupUDP(ack.Port)
		return ok
	}, 2*time.Second, 20*time.Millisecond)
}
