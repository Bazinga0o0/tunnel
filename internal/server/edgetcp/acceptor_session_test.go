package edgetcp_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/client/dialer"
	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

// The edge refuses streams that cannot take a deadline. This test runs it
// against the stream type that a real tunnel session hands out (the
// acceptor's wrapper around a yamux stream): if that wrapper ever loses the
// deadline methods, the edge refuses every stream and this test turns red.
func TestStreamsOfARealTunnelSessionAreAcceptedAndTimeOut(t *testing.T) {
	const token = "twbl_edgetcp_session_test"
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	tunnelLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	defer tunnelLn.Close()

	// A free port for the tunnel's public listener.
	port, _ := testports.FreeTCPRange(t, 1)

	mgr := edgetcp.NewWithOptions(edgetcp.Options{BindHost: "127.0.0.1", Pool: edgetcp.NewPool(port, port), IdleTimeout: 500 * time.Millisecond})
	acc := acceptor.New(acceptor.Options{
		Domain:   "localhost",
		Registry: registry.New(),
		Verifier: auth.NewTokenVerifier([]string{token}),
		TCPEdge:  mgr,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = acc.Serve(ctx, tunnelLn) }()

	sess, err := dialer.New(dialer.Options{ServerAddr: tunnelLn.Addr().String(), Token: token, InsecureSkipVerify: true}).Dial(ctx)
	require.NoError(t, err)
	defer sess.Close()
	ack, err := sess.RegisterTCP(ctx, 0)
	require.NoError(t, err)
	require.Empty(t, ack.Error)
	require.Equal(t, port, ack.Port)

	// The tunnel client answers one message and then neither sends nor closes.
	clientErr := make(chan error, 1)
	go func() {
		st, err := sess.AcceptStream()
		if err != nil {
			clientErr <- err
			return
		}
		if _, err := protocol.ReadStreamHeader(st); err != nil {
			clientErr <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(st, buf); err != nil {
			clientErr <- err
			return
		}
		_, err = st.Write([]byte("pong"))
		clientErr <- err
	}()

	start := time.Now()
	v, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 6*time.Second)
	require.NoError(t, err)
	defer v.Close()
	_, err = v.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_ = v.SetReadDeadline(time.Now().Add(8 * time.Second))
	_, err = io.ReadFull(v, buf)
	require.NoError(t, err, "the stream of a real tunnel session was not accepted by the edge")
	require.Equal(t, "pong", string(buf))
	require.NoError(t, <-clientErr)

	// The deadline reaches the yamux stream through the wrapper: the idle
	// connection is closed although the tunnel client keeps its stream open.
	_ = v.SetReadDeadline(time.Now().Add(8 * time.Second))
	n, err := v.Read(buf)
	require.Zero(t, n)
	require.Error(t, err)
	var ne net.Error
	require.False(t, errors.As(err, &ne) && ne.Timeout(), "the idle connection was not closed")
	require.GreaterOrEqual(t, time.Since(start), 400*time.Millisecond)
}
