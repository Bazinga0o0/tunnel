package edgehttp_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/client/dialer"
	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/edgehttp"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
)

// The edge refuses streams that cannot take a deadline. This test runs it
// against the stream type that a real tunnel session hands out (the
// acceptor's wrapper around a yamux stream): if that wrapper ever loses the
// deadline methods, the edge answers 502 for every request and this test
// turns red.
func TestStreamsOfARealTunnelSessionAreAcceptedAndTimeOut(t *testing.T) {
	const token = "twbl_edgehttp_session_test"
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	tunnelLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	defer tunnelLn.Close()

	reg := registry.New()
	acc := acceptor.New(acceptor.Options{Domain: "localhost", Registry: reg, Verifier: auth.NewTokenVerifier([]string{token})})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = acc.Serve(ctx, tunnelLn) }()

	edge := edgehttp.New(edgehttp.Options{Domain: "localhost", Registry: reg, IdleTimeout: 500 * time.Millisecond})
	srv := httptest.NewUnstartedServer(edge)
	srv.StartTLS()
	defer srv.Close()

	sess, err := dialer.New(dialer.Options{ServerAddr: tunnelLn.Addr().String(), Token: token, InsecureSkipVerify: true}).Dial(ctx)
	require.NoError(t, err)
	defer sess.Close()
	ack, err := sess.RegisterHTTP(ctx, "")
	require.NoError(t, err)
	require.Empty(t, ack.Error)

	// The tunnel client answers one request and then neither sends nor closes.
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
		if _, err := http.ReadRequest(bufio.NewReader(st)); err != nil {
			clientErr <- err
			return
		}
		_, err = st.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong"))
		clientErr <- err
	}()

	start := time.Now()
	v, err := tls.DialWithDialer(&net.Dialer{Timeout: 6 * time.Second}, "tcp", strings.TrimPrefix(srv.URL, "https://"), &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer v.Close()
	_, err = v.Write([]byte("GET / HTTP/1.1\r\nHost: " + ack.Subdomain + ".localhost\r\n\r\n"))
	require.NoError(t, err)
	br := bufio.NewReader(v)
	_ = v.SetReadDeadline(time.Now().Add(8 * time.Second))
	res, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode, "the stream of a real tunnel session was not accepted by the edge")
	require.Equal(t, "pong", string(body))
	require.NoError(t, <-clientErr)

	// The deadline reaches the yamux stream through the wrapper: the idle
	// connection is closed although the tunnel client keeps its stream open.
	_ = v.SetReadDeadline(time.Now().Add(8 * time.Second))
	n, err := br.Read(make([]byte, 1))
	require.Zero(t, n)
	require.Error(t, err)
	var ne net.Error
	require.False(t, errors.As(err, &ne) && ne.Timeout(), "the idle connection was not closed")
	require.GreaterOrEqual(t, time.Since(start), 400*time.Millisecond)
}
