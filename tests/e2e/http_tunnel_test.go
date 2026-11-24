package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/client/connector"
	"github.com/Bazinga0o0/tunnel/internal/client/dialer"
	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/edgehttp"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

func TestHTTPTunnelE2E(t *testing.T) {
	// 1. Local "user" app.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from backend ", r.Host)
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	// 2. Server setup.
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost", "*.localhost"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	reg := registry.New()
	const token = "twbl_e2e_token_00001"
	verifier, err := auth.NewStaticTokenVerifier([]string{token})
	require.NoError(t, err)

	tunnelLn, err := tls.Listen("tcp", testports.Loopback+":0", tlsCfg)
	require.NoError(t, err)
	defer tunnelLn.Close()

	httpLn, err := tls.Listen("tcp", testports.Loopback+":0", tlsCfg)
	require.NoError(t, err)
	defer httpLn.Close()

	acc := acceptor.New(acceptor.Options{Domain: "localhost", Registry: reg, Verifier: verifier})
	edge := edgehttp.New(edgehttp.Options{Domain: "localhost", Registry: reg})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpSrv := &http.Server{Handler: edge}
	go acc.Serve(ctx, tunnelLn)
	go httpSrv.Serve(httpLn)

	// 3. Client dials + registers.
	d := dialer.New(dialer.Options{
		ServerAddr:         tunnelLn.Addr().String(),
		Token:              token,
		InsecureSkipVerify: true,
	})
	sess, err := d.Dial(ctx)
	require.NoError(t, err)
	defer sess.Close()

	ack, err := sess.RegisterHTTP(ctx, "")
	require.NoError(t, err)
	require.Empty(t, ack.Error)

	conn := connector.New(connector.Options{LocalAddr: backendAddr, ExpectedType: "http"})
	go func() {
		for {
			stream, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go conn.Handle(stream)
		}
	}()

	require.Eventually(t, func() bool {
		_, ok := reg.LookupHTTP(ack.Subdomain)
		return ok
	}, 2*time.Second, 20*time.Millisecond)

	// 4. Issue request via edge.
	edgeAddr := httpLn.Addr().String()
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialTLSContext: func(ctx context.Context, network, a string) (net.Conn, error) {
				return tls.Dial("tcp", edgeAddr, &tls.Config{InsecureSkipVerify: true, ServerName: ack.Subdomain + ".localhost"})
			},
		},
	}
	req, _ := http.NewRequest("GET", "https://"+ack.Subdomain+".localhost/", nil)
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	require.Contains(t, string(body), "hello from backend")
}
