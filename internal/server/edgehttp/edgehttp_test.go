package edgehttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

type fakeTunnelSession struct {
	id       string
	incoming chan protocol.Stream
}

func (f *fakeTunnelSession) ID() string { return f.id }

func (f *fakeTunnelSession) OpenStream() (protocol.Stream, error) {
	a, b := protocol.PipeStream()
	f.incoming <- a
	return b, nil
}

func TestEdgeHTTPRoutesByHost(t *testing.T) {
	reg := registry.New()
	fake := &fakeTunnelSession{id: "s1", incoming: make(chan protocol.Stream, 1)}
	require.NoError(t, reg.RegisterHTTP("abc", fake))

	edge := New(Options{Domain: "localhost", Registry: reg})

	ts := httptest.NewUnstartedServer(edge)
	ts.StartTLS()
	defer ts.Close()

	addr := strings.TrimPrefix(ts.URL, "https://")
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialTLSContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "abc.localhost"})
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	go func() {
		stream := <-fake.incoming
		defer stream.Close()

		hdr, err := protocol.ReadStreamHeader(stream)
		require.NoError(t, err)
		require.Equal(t, protocol.StreamTypeHTTP, hdr.StreamType)
		require.Equal(t, "abc.localhost", hdr.OriginalHost)

		buf := make([]byte, 4096)
		_, _ = stream.Read(buf)

		resp := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
		_, _ = stream.Write([]byte(resp))
	}()

	req, _ := http.NewRequest("GET", "https://abc.localhost/", nil)
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	require.Equal(t, "hello", strings.TrimSpace(string(body)))
}

func TestEdgeHTTPForwardsLargePOSTBody(t *testing.T) {
	reg := registry.New()
	fake := &fakeTunnelSession{id: "s1", incoming: make(chan protocol.Stream, 1)}
	require.NoError(t, reg.RegisterHTTP("abc", fake))

	edge := New(Options{Domain: "localhost", Registry: reg})

	ts := httptest.NewUnstartedServer(edge)
	ts.StartTLS()
	defer ts.Close()

	body := bytes.Repeat([]byte("a"), 32*1024)

	go func() {
		stream := <-fake.incoming
		defer stream.Close()

		hdr, err := protocol.ReadStreamHeader(stream)
		require.NoError(t, err)
		require.Equal(t, protocol.StreamTypeHTTP, hdr.StreamType)

		br := bufio.NewReader(stream)
		req, err := http.ReadRequest(br)
		require.NoError(t, err)
		got, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		require.Equal(t, len(body), len(got))
		require.Equal(t, body, got)

		_, _ = stream.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok!"))
	}()

	addr := strings.TrimPrefix(ts.URL, "https://")
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialTLSContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "abc.localhost"})
		},
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	req, _ := http.NewRequest("POST", "https://abc.localhost/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	gotResp, _ := io.ReadAll(res.Body)
	require.Equal(t, "ok!", strings.TrimSpace(string(gotResp)))
}

func TestEdgeHTTPUnknownHostReturns404(t *testing.T) {
	reg := registry.New()
	edge := New(Options{Domain: "localhost", Registry: reg})

	ts := httptest.NewUnstartedServer(edge)
	ts.StartTLS()
	defer ts.Close()

	addr := strings.TrimPrefix(ts.URL, "https://")
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialTLSContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "nope.localhost"})
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("GET", "https://nope.localhost/", nil)
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusNotFound, res.StatusCode)
}
