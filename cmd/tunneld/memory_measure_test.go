package main

// The measurement behind the memory constants (see memory.go). It is not part
// of the normal test run: set TUNNELD_MEASURE_MEMORY=1 to run it, for example
//
//	TUNNELD_MEASURE_MEMORY=1 go test -count=1 -run '^TestMeasureMemory$' -v -timeout 20m ./cmd/tunneld/
//
// The server side (acceptor, edges, public HTTPS listener) runs in the test
// process; the tunnel client and the visitors run in a child process (this
// test binary again, see TestMeasureMemoryChild), so that the numbers are the
// server's alone. For every scenario the test takes the live heap and the
// goroutine stacks after a full GC before the child starts, starts the child,
// waits until the server's memory stops growing, takes them again and divides
// the difference by the number of units.
//
// The retained-session modes measure closed sessions that yamux keeps while
// a close timer of the server is pending. Run "retained-session-fired"
// before "retained-session" and shorten the timers, for example
//
//	TUNNELD_MEASURE_MEMORY=1 TUNNELD_MEASURE_UNITS=20 TUNNELD_MEASURE_CLOSE_TIMEOUT=30s \
//	TUNNELD_MEASURE_MODES=retained-session-fired,retained-session \
//	go test -count=1 -run '^TestMeasureMemory$' -v -timeout 10m ./cmd/tunneld/
//
// "-fired" waits until its timers have run out; the other mode is measured
// while they are pending, and the next mode's baseline would still contain
// them.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/client/dialer"
	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/acceptor"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/edgehttp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeudp"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
	"github.com/Bazinga0o0/tunnel/internal/testports"
)

const measureToken = "twbl_memory_measurement_token"

// Environment of the child process.
const (
	envMeasure      = "TUNNELD_MEASURE_MEMORY"
	envChildMode    = "TUNNELD_MEASURE_CHILD"
	envChildTunnel  = "TUNNELD_MEASURE_TUNNEL_ADDR"
	envChildPublic  = "TUNNELD_MEASURE_PUBLIC_ADDR"
	envChildUnits   = "TUNNELD_MEASURE_UNITS"
	envChildUDPPort = "TUNNELD_MEASURE_UDP_PORT"
	// envCloseTimeout shortens the server's StreamCloseTimeout for the
	// retained-session modes (a Go duration; default yamux's 5m).
	envCloseTimeout = "TUNNELD_MEASURE_CLOSE_TIMEOUT"
)

// closeTimeout is the server's StreamCloseTimeout in the measurement.
func closeTimeout() time.Duration {
	if d, err := time.ParseDuration(os.Getenv(envCloseTimeout)); err == nil && d > 0 {
		return d
	}
	return 5 * time.Minute
}

// measureServer is the server side of the measurement.
type measureServer struct {
	tunnelAddr string
	publicAddr string
	tcpLow     int
	udpLow     int
}

func startMeasureServer(t *testing.T, ports int) *measureServer {
	t.Helper()
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"tunnel.test", "*.tunnel.test"})
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tcpLow, tcpHigh := testports.FreeTCPRange(t, ports)
	udpLow, udpHigh := testports.FreeUDPRange(t, ports)
	reg := registry.New()
	acc := acceptor.New(acceptor.Options{
		Domain: "tunnel.test", Registry: reg, Logger: logger,
		Verifier:             auth.NewTokenVerifier([]string{measureToken}),
		HandshakeTimeout:     10 * time.Minute, // the handshake scenario stalls inside it
		MaxUnauthConns:       -1,
		MaxUnauthConnsPerIP:  -1,
		MaxStreamsPerSession: -1,
		MaxSessions:          -1,
		ControlBurst:         -1,
		StreamCloseTimeout:   closeTimeout(),
		TCPEdge: edgetcp.NewWithOptions(edgetcp.Options{
			BindHost: testports.Loopback, Pool: edgetcp.NewPool(tcpLow, tcpHigh), Logger: logger,
			MaxConnsPerTunnel: -1, MaxConnsPerIP: -1, MaxConns: -1,
		}),
		UDPEdge: edgeudp.New(edgeudp.Options{
			BindHost: testports.Loopback, Pool: edgeudp.NewPool(udpLow, udpHigh), Logger: logger,
			MaxFlowsPerPort: -1, MaxFlowsPerIP: -1, MaxFlows: -1,
		}),
	})
	tunnelLn, err := tls.Listen("tcp", testports.Loopback+":0", tlsConfig)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = acc.Serve(ctx, tunnelLn) }()

	// A long header timeout keeps the connections of the header scenario
	// open while they are measured.
	s := config.HTTPServer{MaxConns: -1, MaxConnsPerIP: -1, ReadHeaderTimeout: 10 * time.Minute}
	edge := edgehttp.New(edgehttp.Options{Domain: "tunnel.test", Registry: reg, Logger: logger,
		MaxConnsPerTunnel: -1, MaxConnsPerIP: -1, MaxConns: -1})
	publicLn, err := listenPublic(testports.Loopback+":0", tlsConfig, s, logger)
	require.NoError(t, err)
	srv := newPublicServer(dispatchHost("tunnel.test", http.NotFoundHandler(), edge, nil, s), s, logger)
	go func() { _ = srv.Serve(publicLn) }()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		_ = tunnelLn.Close()
	})
	return &measureServer{
		tunnelAddr: tunnelLn.Addr().String(), publicAddr: publicLn.Addr().String(),
		tcpLow: tcpLow, udpLow: udpLow,
	}
}

// memSample is what the measurement reads from the runtime after a full GC.
type memSample struct {
	heap, stack uint64
	goroutines  int
}

func sample() memSample {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return memSample{heap: m.HeapAlloc, stack: m.StackInuse, goroutines: runtime.NumGoroutine()}
}

// quiesce waits until the goroutines of the scenario before have ended: the
// count stays the same for a second.
func quiesce() {
	deadline := time.Now().Add(20 * time.Second)
	last, same := runtime.NumGoroutine(), 0
	for same < 5 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		if n := runtime.NumGoroutine(); n == last {
			same++
		} else {
			last, same = n, 0
		}
	}
}

// settle waits until the server's memory stops growing: three samples half a
// second apart that differ by less than 0.5 % of the growth so far.
func settle(base memSample, deadline time.Time) memSample {
	prev := sample()
	stable := 0
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		cur := sample()
		growth := float64(cur.heap+cur.stack) - float64(base.heap+base.stack)
		diff := float64(cur.heap+cur.stack) - float64(prev.heap+prev.stack)
		if diff < 0 {
			diff = -diff
		}
		if growth > 0 && diff < growth*0.005 {
			stable++
			if stable >= 3 {
				return cur
			}
		} else {
			stable = 0
		}
		prev = cur
	}
	return prev
}

type measurement struct {
	scenario   string
	units      int
	heap       float64 // bytes per unit
	stack      float64
	goroutines float64
}

func (m measurement) String() string {
	return fmt.Sprintf("%-28s units=%5d  heap/unit=%8.1f KiB  stack/unit=%6.1f KiB  total/unit=%8.1f KiB  goroutines/unit=%.2f",
		m.scenario, m.units, m.heap/1024, m.stack/1024, (m.heap+m.stack)/1024, m.goroutines)
}

// measure runs the child in mode with units and returns the server's memory
// per unit.
func measure(t *testing.T, srv *measureServer, mode string, units int, udpPort int) measurement {
	t.Helper()
	quiesce()
	base := sample()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMeasureMemoryChild$", "-test.timeout=30m")
	cmd.Env = append(os.Environ(),
		envChildMode+"="+mode,
		envChildTunnel+"="+srv.tunnelAddr,
		envChildPublic+"="+srv.publicAddr,
		envChildUnits+"="+strconv.Itoa(units),
		envChildUDPPort+"="+strconv.Itoa(udpPort),
	)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	defer func() {
		_ = stdin.Close() // the child ends when its stdin closes
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		time.Sleep(2 * time.Second) // let the server tear the sessions down
	}()

	ready := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "READY") {
				ready <- nil
			}
			if strings.HasPrefix(line, "CHILD ERROR") {
				ready <- fmt.Errorf("%s", line)
			}
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case err := <-ready:
		require.NoError(t, err)
	case <-time.After(5 * time.Minute):
		t.Fatalf("%s: the child did not get ready", mode)
	}
	after := settle(base, time.Now().Add(3*time.Minute))
	return measurement{
		scenario:   mode,
		units:      units,
		heap:       (float64(after.heap) - float64(base.heap)) / float64(units),
		stack:      (float64(after.stack) - float64(base.stack)) / float64(units),
		goroutines: float64(after.goroutines-base.goroutines) / float64(units),
	}
}

func TestMeasureMemory(t *testing.T) {
	if os.Getenv(envMeasure) == "" {
		t.Skip("set " + envMeasure + "=1 to measure the memory cost of streams, sessions and connections")
	}
	units := 200
	if n, err := strconv.Atoi(os.Getenv(envChildUnits)); err == nil && n > 0 {
		units = n
	}
	srv := startMeasureServer(t, units+10)
	var results []measurement
	modes := []string{"session", "session-http", "session-tcp", "session-udp", "public-conn", "public-conn-header",
		"public-handshake", "tunnel-handshake", "tcp-stream", "http-stream",
		"udp-flow-idle", "udp-flow-burst", "udp-flow-middatagram",
		"tcp-linger", "http-linger", "udp-linger", "retained-session", "retained-session-fired"}
	if m := os.Getenv("TUNNELD_MEASURE_MODES"); m != "" {
		modes = strings.Split(m, ",")
	}
	for _, mode := range modes {
		n := units
		if strings.HasPrefix(mode, "public-conn") {
			n = units * 5
		}
		m := measure(t, srv, mode, n, srv.udpLow)
		t.Log(m.String())
		results = append(results, m)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s/%s GOMAXPROCS=%d\n", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0))
	for _, m := range results {
		b.WriteString(m.String() + "\n")
	}
	if out := os.Getenv("TUNNELD_MEASURE_OUT"); out != "" {
		require.NoError(t, os.WriteFile(out, []byte(b.String()), 0o600))
	}
	t.Log("\n" + b.String())
}

// ---- the child: tunnel client and visitors ----

// TestMeasureMemoryChild is the child process of TestMeasureMemory.
func TestMeasureMemoryChild(t *testing.T) {
	mode := os.Getenv(envChildMode)
	if mode == "" {
		t.Skip("child process of TestMeasureMemory")
	}
	units, _ := strconv.Atoi(os.Getenv(envChildUnits))
	tunnelAddr, publicAddr := os.Getenv(envChildTunnel), os.Getenv(envChildPublic)
	var keep []io.Closer
	defer func() {
		for _, c := range keep {
			_ = c.Close()
		}
	}()
	fail := func(err error) {
		fmt.Printf("CHILD ERROR %s: %v\n", mode, err)
		t.FailNow()
	}
	ctx := context.Background()
	dial := func() *dialer.Session {
		s, err := dialer.New(dialer.Options{ServerAddr: tunnelAddr, Token: measureToken, InsecureSkipVerify: true}).Dial(ctx)
		if err != nil {
			fail(err)
		}
		keep = append(keep, s)
		return s
	}

	switch mode {
	case "session":
		for i := 0; i < units; i++ {
			dial()
		}
	case "public-conn":
		for i := 0; i < units; i++ {
			c, err := tls.Dial("tcp", publicAddr, &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				fail(err)
			}
			keep = append(keep, c)
		}
	case "public-conn-header":
		// A request head of 60 KiB that never ends: the server holds what
		// it has read of it until the header timeout.
		head := "GET / HTTP/1.1\r\nHost: tunnel.test\r\nX-Pad: " + strings.Repeat("a", 60<<10)
		for i := 0; i < units; i++ {
			c, err := tls.Dial("tcp", publicAddr, &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				fail(err)
			}
			if _, err := c.Write([]byte(head)); err != nil {
				fail(err)
			}
			keep = append(keep, c)
		}
	case "tcp-stream":
		s := dial()
		ack, err := s.RegisterTCP(ctx, 0)
		if err != nil || ack.Error != "" {
			fail(fmt.Errorf("register tcp: %v %s", err, ack.Error))
		}
		go floodStreams(s, "")
		for i := 0; i < units; i++ {
			c, err := net.Dial("tcp", net.JoinHostPort(testports.Loopback, strconv.Itoa(ack.Port)))
			if err != nil {
				fail(err)
			}
			keep = append(keep, c) // never read
		}
	case "http-stream":
		s := dial()
		ack, err := s.RegisterHTTP(ctx, "measure")
		if err != nil || ack.Error != "" {
			fail(fmt.Errorf("register http: %v", err))
		}
		go floodStreams(s, "")
		for i := 0; i < units; i++ {
			c, err := tls.Dial("tcp", publicAddr, &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				fail(err)
			}
			if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: measure.tunnel.test\r\n\r\n")); err != nil {
				fail(err)
			}
			keep = append(keep, c) // never read
		}
	case "session-http", "session-tcp", "session-udp":
		for i := 0; i < units; i++ {
			s := dial()
			var text string
			var err error
			switch mode {
			case "session-http":
				var ack *protocol.RegisterHTTPAck
				ack, err = s.RegisterHTTP(ctx, fmt.Sprintf("m%05d", i))
				if ack != nil {
					text = ack.Error
				}
			case "session-tcp":
				var ack *protocol.RegisterTCPAck
				ack, err = s.RegisterTCP(ctx, 0)
				if ack != nil {
					text = ack.Error
				}
			default:
				var ack *protocol.RegisterUDPAck
				ack, err = s.RegisterUDP(ctx, 0)
				if ack != nil {
					text = ack.Error
				}
			}
			if err != nil || text != "" {
				fail(fmt.Errorf("%s %d: %v %s", mode, i, err, text))
			}
		}
	case "public-handshake", "tunnel-handshake":
		// A ClientHello of almost 64 KiB (crypto/tls accepts handshake
		// messages up to 64 KiB) of which all but a few bytes arrive: the
		// server holds what it has read until the handshake deadline.
		addr := publicAddr
		if mode == "tunnel-handshake" {
			addr = tunnelAddr
		}
		msgLen := 65000
		msg := make([]byte, 4+msgLen-16)
		msg[0] = 1 // ClientHello
		msg[1], msg[2], msg[3] = byte(msgLen>>16), byte(msgLen>>8), byte(msgLen)
		for i := 0; i < units; i++ {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				fail(err)
			}
			for rest := msg; len(rest) > 0; {
				n := min(len(rest), 16384)
				rec := append([]byte{22, 3, 1, byte(n >> 8), byte(n)}, rest[:n]...)
				if _, err := c.Write(rec); err != nil {
					fail(err)
				}
				rest = rest[n:]
			}
			keep = append(keep, c)
		}
	case "udp-flow-idle", "udp-flow-burst", "udp-flow-middatagram":
		s := dial()
		ack, err := s.RegisterUDP(ctx, 0)
		if err != nil || ack.Error != "" {
			fail(fmt.Errorf("register udp: %v", err))
		}
		go floodStreams(s, strings.TrimPrefix(mode, "udp-flow-"))
		raddr := &net.UDPAddr{IP: net.ParseIP(testports.Loopback), Port: ack.Port}
		var visitors []*net.UDPConn
		for i := 0; i < units; i++ {
			c, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				fail(err)
			}
			if _, err := c.Write([]byte("hello")); err != nil {
				fail(err)
			}
			keep = append(keep, c)
			visitors = append(visitors, c)
		}
		// A datagram every five seconds keeps each flow within the idle
		// timeout while it is measured.
		go func() {
			for range time.Tick(5 * time.Second) {
				for _, c := range visitors {
					_, _ = c.Write([]byte("keepalive"))
				}
			}
		}()
	case "tcp-linger", "http-linger":
		// The edge is done with the stream, the tunnel client is not: every
		// visitor leaves at once, the client keeps each stream open and
		// writes on it as fast as it can (floodStreams).
		s := dial()
		var port int
		if mode == "tcp-linger" {
			ack, err := s.RegisterTCP(ctx, 0)
			if err != nil || ack.Error != "" {
				fail(fmt.Errorf("register tcp: %v %s", err, ack.Error))
			}
			port = ack.Port
		} else {
			ack, err := s.RegisterHTTP(ctx, "measure")
			if err != nil || ack.Error != "" {
				fail(fmt.Errorf("register http: %v", err))
			}
		}
		go floodStreams(s, "")
		for i := 0; i < units; i++ {
			var c net.Conn
			var err error
			if mode == "tcp-linger" {
				c, err = net.Dial("tcp", net.JoinHostPort(testports.Loopback, strconv.Itoa(port)))
			} else {
				c, err = tls.Dial("tcp", publicAddr, &tls.Config{InsecureSkipVerify: true})
				if err == nil {
					_, err = c.Write([]byte("GET / HTTP/1.1\r\nHost: measure.tunnel.test\r\n\r\n"))
				}
			}
			if err != nil {
				fail(err)
			}
			_ = c.Close()
		}
		time.Sleep(3 * time.Second) // the edge notices that every visitor has left
	case "retained-session", "retained-session-fired":
		// The cheapest way an account holder has to leave closed sessions in
		// the server's memory: in every session its own visitor half-closes a
		// TCP connection, so that the edge closes the stream (a close timer
		// pending, as the client never answers with a FIN), and then the
		// client disconnects. The server's session ends while the timer
		// holds it. "-fired" waits until the timers have run out.
		for i := 0; i < units; i++ {
			retainSession(ctx, tunnelAddr, fail)
		}
		if mode == "retained-session-fired" {
			time.Sleep(closeTimeout() + 10*time.Second)
		}
	case "udp-linger":
		// Every visitor sends one datagram and nothing more, so its flow
		// idles out (30 s); the tunnel client keeps each flow's stream open
		// and writes datagrams on it as fast as it can.
		s := dial()
		ack, err := s.RegisterUDP(ctx, 0)
		if err != nil || ack.Error != "" {
			fail(fmt.Errorf("register udp: %v", err))
		}
		go floodStreams(s, "burst")
		raddr := &net.UDPAddr{IP: net.ParseIP(testports.Loopback), Port: ack.Port}
		for i := 0; i < units; i++ {
			c, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				fail(err)
			}
			if _, err := c.Write([]byte("hello")); err != nil {
				fail(err)
			}
			keep = append(keep, c)
		}
		time.Sleep(45 * time.Second) // idle timeout and sweep interval, with margin
	default:
		fail(fmt.Errorf("unknown mode"))
	}
	time.Sleep(time.Second)
	fmt.Println("READY")
	_, _ = io.Copy(io.Discard, os.Stdin) // until the parent closes stdin
}

// retainSession makes one session that ends while a close timer of the
// server is pending (see the retained-session modes).
func retainSession(ctx context.Context, tunnelAddr string, fail func(error)) {
	s, err := dialer.New(dialer.Options{ServerAddr: tunnelAddr, Token: measureToken, InsecureSkipVerify: true}).Dial(ctx)
	if err != nil {
		fail(err)
	}
	ack, err := s.RegisterTCP(ctx, 0)
	if err != nil || ack.Error != "" {
		fail(fmt.Errorf("register tcp: %v %s", err, ack.Error))
	}
	streams := make(chan protocol.Stream, 1)
	go func() {
		st, err := s.AcceptStream()
		if err != nil {
			return
		}
		if _, err := protocol.ReadStreamHeader(st); err != nil {
			return
		}
		streams <- st
	}()
	c, err := net.Dial("tcp", net.JoinHostPort(testports.Loopback, strconv.Itoa(ack.Port)))
	if err != nil {
		fail(err)
	}
	if _, err := c.Write([]byte("x")); err != nil {
		fail(err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		fail(err)
	}
	var st protocol.Stream
	select {
	case st = <-streams:
	case <-time.After(10 * time.Second):
		fail(fmt.Errorf("the visitor's stream did not arrive"))
	}
	// The visitor's byte, then the edge's close of the stream: EOF.
	if _, err := io.ReadAll(st); err != nil {
		fail(err)
	}
	// The client disconnects without closing the stream.
	_ = s.Close()
	_ = c.Close()
}

// floodStreams accepts the server's streams. On TCP and HTTP streams it
// writes as fast as it can. On UDP streams udp decides: "burst" writes
// datagrams as fast as it can, "middatagram" writes the header of a
// datagram of 65535 bytes and ten bytes of it and then nothing, anything
// else writes nothing.
func floodStreams(s *dialer.Session, udp string) {
	var mu sync.Mutex
	var streams []protocol.Stream
	for {
		st, err := s.AcceptStream()
		if err != nil {
			return
		}
		mu.Lock()
		streams = append(streams, st)
		mu.Unlock()
		go func() {
			hdr, err := protocol.ReadStreamHeader(st)
			if err != nil {
				return
			}
			switch hdr.StreamType {
			case protocol.StreamTypeUDP:
				if udp == "middatagram" {
					_, _ = st.Write(append([]byte{0xff, 0xff}, make([]byte, 10)...))
					return
				}
				if udp != "burst" {
					return
				}
				payload := make([]byte, 60<<10)
				for {
					if err := protocol.WriteDatagram(st, payload); err != nil {
						return
					}
				}
			default:
				// The receive buffer of a yamux stream is allocated at the
				// size of the first frame and doubles when a frame does not
				// fit. A first frame just below the window and then small
				// frames make it reach about twice the window: the worst
				// case a client can choose. TUNNELD_MEASURE_PATTERN=steady
				// writes 32 KiB chunks only.
				if os.Getenv("TUNNELD_MEASURE_PATTERN") != "steady" {
					if _, err := st.Write(make([]byte, protocol.StreamWindowBytes-1024)); err != nil {
						return
					}
				}
				chunk := make([]byte, 1<<10)
				if os.Getenv("TUNNELD_MEASURE_PATTERN") == "steady" {
					chunk = make([]byte, 32<<10)
				}
				for {
					if _, err := st.Write(chunk); err != nil {
						return
					}
				}
			}
		}()
	}
}
