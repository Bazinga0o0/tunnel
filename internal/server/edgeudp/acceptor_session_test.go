package edgeudp_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/client/dialer"
	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeudp"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

// The edge refuses streams that cannot take a deadline. This test runs it
// against the stream type that a real tunnel session hands out (the
// acceptor's wrapper around a yamux stream): if that wrapper ever loses the
// deadline methods, the edge refuses every stream and this test turns red.
func TestStreamsOfARealTunnelSessionAreAcceptedAndExpire(t *testing.T) {
	const token = "twbl_edgeudp_session_test"
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	tunnelLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	defer tunnelLn.Close()

	// A free port for the tunnel's public socket.
	port, _ := testports.FreeUDPRange(t, 1)

	mgr := edgeudp.New(edgeudp.Options{BindHost: "127.0.0.1", Pool: edgeudp.NewPool(port, port), IdleTimeout: 500 * time.Millisecond, SweepInterval: 20 * time.Millisecond})
	acc := acceptor.New(acceptor.Options{
		Domain:   "localhost",
		Registry: registry.New(),
		Verifier: auth.NewTokenVerifier([]string{token}),
		UDPEdge:  mgr,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = acc.Serve(ctx, tunnelLn) }()

	sess, err := dialer.New(dialer.Options{ServerAddr: tunnelLn.Addr().String(), Token: token, InsecureSkipVerify: true}).Dial(ctx)
	require.NoError(t, err)
	defer sess.Close()
	ack, err := sess.RegisterUDP(ctx, 0)
	require.NoError(t, err)
	require.Empty(t, ack.Error)
	require.Equal(t, port, ack.Port)

	// The tunnel client answers one datagram and then neither sends nor
	// closes; it reports when the edge has ended the stream.
	answered := make(chan error, 1)
	ended := make(chan struct{})
	go func() {
		st, err := sess.AcceptStream()
		if err != nil {
			answered <- err
			return
		}
		if _, err := protocol.ReadStreamHeader(st); err != nil {
			answered <- err
			return
		}
		if _, err := protocol.ReadDatagram(st, nil); err != nil {
			answered <- err
			return
		}
		answered <- protocol.WriteDatagram(st, []byte("pong"))
		for {
			if _, err := protocol.ReadDatagram(st, nil); err != nil {
				close(ended)
				return
			}
		}
	}()

	v, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	require.NoError(t, err)
	defer v.Close()
	_, err = v.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 16)
	_ = v.SetReadDeadline(time.Now().Add(8 * time.Second))
	n, err := v.Read(buf)
	require.NoError(t, err, "the stream of a real tunnel session was not accepted by the edge")
	require.Equal(t, "pong", string(buf[:n]))
	require.NoError(t, <-answered)

	// The idle flow is evicted and its stream ended, also towards the client.
	select {
	case <-ended:
	case <-time.After(8 * time.Second):
		t.Fatal("the stream of the idle flow was not ended")
	}
}
