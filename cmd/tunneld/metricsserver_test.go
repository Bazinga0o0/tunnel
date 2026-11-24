package main

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/testports"
)

func TestMetricsServerServesTheMetrics(t *testing.T) {
	logger, logs := captureLog()
	srv, addr, err := startMetricsServer(testports.Loopback+":0", logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	defer shutdownServer(srv, time.Second)

	res, err := http.Get("http://" + addr + metricsPath)
	require.NoError(t, err)
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, string(body), "tunneld_cert_not_after_unix")
	assert.Contains(t, logs.String(), "metrics endpoint enabled")

	// The endpoint has timeouts like any other server.
	assert.Positive(t, srv.ReadHeaderTimeout)
	assert.Positive(t, srv.ReadTimeout)
	assert.Positive(t, srv.WriteTimeout)
	assert.Positive(t, srv.IdleTimeout)
	assert.Positive(t, srv.MaxHeaderBytes)
}

func TestEmptyMetricsAddressDisablesTheEndpoint(t *testing.T) {
	logger, logs := captureLog()
	srv, addr, err := startMetricsServer("", logger)
	require.NoError(t, err)
	assert.Nil(t, srv)
	assert.Empty(t, addr)
	assert.Contains(t, logs.String(), "metrics endpoint disabled")
	shutdownServer(nil, time.Second) // harmless
}

func TestMetricsBindErrorAbortsTheStart(t *testing.T) {
	taken, err := net.Listen("tcp", testports.Loopback+":0")
	require.NoError(t, err)
	defer taken.Close()

	logger, _ := captureLog()
	srv, _, err := startMetricsServer(taken.Addr().String(), logger)
	require.Error(t, err)
	assert.Nil(t, srv)
	assert.Contains(t, err.Error(), "metrics")
}

func TestShutdownServerHasADeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release // a request that never finishes
	})}
	ln, err := net.Listen("tcp", testports.Loopback+":0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(ln) }()

	// The client waits far longer than the test does: only the server can
	// end this request in time.
	client := &http.Client{Timeout: 10 * time.Minute}
	reqDone := make(chan error, 1)
	go func() {
		res, err := client.Get("http://" + ln.Addr().String() + "/")
		if err == nil {
			_ = res.Body.Close()
		}
		reqDone <- err
	}()
	<-entered

	start := time.Now()
	shutdownServer(srv, 200*time.Millisecond)
	assert.Less(t, time.Since(start), 5*time.Second, "shutdown gives up at its deadline")
	select {
	case err := <-reqDone:
		assert.Error(t, err, "the hanging request was cut")
	case <-time.After(10 * time.Second):
		t.Fatal("the hanging connection is still open after the shutdown")
	}
	_, err = net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	assert.Error(t, err, "the listener is closed")
}
