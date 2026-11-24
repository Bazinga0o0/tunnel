package acceptor

import (
	"context"
	"encoding/binary"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
)

// pipeListener hands the acceptor the server ends of in-memory pipes. A pipe
// has no buffer: a write waits until the other side reads, which is what a
// TCP connection does once a peer that does not read has let its buffers
// fill. It brings the scenario to a test in milliseconds.
type pipeListener struct {
	conns chan net.Conn
	once  sync.Once
	done  chan struct{}
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7443} }

// dial returns the client end of a new connection.
func (l *pipeListener) dial() net.Conn {
	client, server := net.Pipe()
	l.conns <- server
	return client
}

// pingLimitCount reads tunneld_request_total{type="tunnel",status="ping_limit"}.
func pingLimitCount(t *testing.T) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, metrics.RequestTotal.WithLabelValues("tunnel", "ping_limit").Write(&m))
	return m.GetCounter().GetValue()
}

// pingRequest is a yamux ping frame with the SYN flag.
func pingRequest(id uint32) []byte {
	b := make([]byte, 12)
	b[1] = 2 // ping
	binary.BigEndian.PutUint16(b[2:4], 1)
	binary.BigEndian.PutUint32(b[8:12], id)
	return b
}

// An outsider who has not logged in sends yamux ping requests and reads
// nothing. yamux answers each from a goroutine of its own, which waits up to
// 10 s for the blocked connection; without the ping guard the goroutines
// grow with the pings (about 8 KiB each). With it, the connection is closed
// once the allowance is used up and the goroutines go back to where they
// were.
func TestPingFloodBeforeLoginClosesTheConnection(t *testing.T) {
	logger, logs := captureLogger()
	opts := staticOpts()
	opts.Registry = registry.New()
	opts.Logger = logger
	acc := New(opts)
	ln := newPipeListener()
	ctx, cancel := context.WithCancel(context.Background())
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

	before := pingLimitCount(t)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	conn := ln.dial()
	defer conn.Close()
	const pings = 3000
	sent := 0
	for i := uint32(1); i <= pings; i++ {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(pingRequest(i)); err != nil {
			break
		}
		sent++
	}
	peak := runtime.NumGoroutine()
	t.Logf("sent %d of %d ping requests; goroutines %d before, %d after", sent, pings, baseline, peak)

	assert.Less(t, sent, pings, "the connection was closed before all pings were taken")
	assert.Less(t, peak-baseline, 100, "the goroutines did not grow with the pings")
	require.Eventually(t, func() bool { return runtime.NumGoroutine() <= baseline+2 }, waitFor, 20*time.Millisecond,
		"the goroutines of the closed connection end (now %d, baseline %d)", runtime.NumGoroutine(), baseline)

	assert.Equal(t, before+1, pingLimitCount(t))
	assert.Equal(t, 1, strings.Count(logs.String(), `msg="too many ping requests, closing tunnel connection"`), logs.String())
}
