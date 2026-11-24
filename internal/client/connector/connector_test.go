package connector

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// --- helpers ----------------------------------------------------------------

// localApp is a TCP server standing in for the user's local service. Every
// accepted connection is handed to serve; conns counts them.
type localApp struct {
	ln    net.Listener
	mu    sync.Mutex
	conns int
}

func startLocalApp(t *testing.T, serve func(conn net.Conn)) *localApp {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	app := &localApp{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			app.mu.Lock()
			app.conns++
			app.mu.Unlock()
			go func() {
				defer conn.Close()
				serve(conn)
			}()
		}
	}()
	return app
}

func (a *localApp) addr() string { return a.ln.Addr().String() }

func (a *localApp) connections() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.conns
}

// echoUpper answers every line with its upper-case form.
func echoUpper(conn net.Conn) {
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		fmt.Fprintf(conn, "%s\n", strings.ToUpper(sc.Text()))
	}
}

// handleAsync runs c.Handle(stream) and delivers its result.
func handleAsync(c *Connector, stream protocol.Stream) <-chan error {
	done := make(chan error, 1)
	go func() { done <- c.Handle(stream) }()
	return done
}

// result waits for a Handle result and fails the test when it takes too long.
func result(t *testing.T, done <-chan error, limit time.Duration) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("Handle did not return within %s", limit)
		return nil
	}
}

func stillRunning(t *testing.T, done <-chan error, wait time.Duration) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("Handle returned early: %v", err)
	case <-time.After(wait):
	}
}

func setReadDeadline(t *testing.T, s protocol.Stream, d time.Duration) {
	t.Helper()
	require.NoError(t, s.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(time.Now().Add(d)))
}

// readLine reads one line from the server side of a stream.
func readLine(t *testing.T, s protocol.Stream) string {
	t.Helper()
	setReadDeadline(t, s, 5*time.Second)
	line, err := bufio.NewReader(s).ReadString('\n')
	require.NoError(t, err)
	return line
}

// expectClosed asserts that the connector closed its end of the stream.
func expectClosed(t *testing.T, serverSide protocol.Stream) {
	t.Helper()
	// Setting a deadline fails on a pipe whose other end is already closed;
	// the read below then returns EOF right away, which is what is checked.
	_ = serverSide.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := serverSide.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "the connector must have closed the stream")
}

func assertASCIIPrintable(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			t.Errorf("rune %U in %q is not printable ASCII", r, s)
		}
	}
}

// --- piping -----------------------------------------------------------------

func TestHandleStreamPipesToLocal(t *testing.T) {
	// Start a local fake "app": accept one connection, echo back "hello".
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer localLn.Close()

	var localDone sync.WaitGroup
	localDone.Add(1)
	go func() {
		defer localDone.Done()
		conn, err := localLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		line, _ := br.ReadString('\n')
		_ = line
		fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
	}()

	// Simulate the server side of a data stream.
	serverSide, clientSide := protocol.PipeStream()

	c := New(Options{LocalAddr: localLn.Addr().String(), ExpectedType: protocol.StreamTypeHTTP})

	connectorDone := make(chan struct{})
	go func() {
		defer close(connectorDone)
		_ = c.Handle(clientSide)
	}()

	// Server writes header + request
	hdr := &protocol.StreamHeader{StreamType: protocol.StreamTypeHTTP, OriginalHost: "abc.localhost"}
	require.NoError(t, protocol.WriteStreamHeader(serverSide, hdr))
	_, _ = fmt.Fprint(serverSide, "GET / HTTP/1.1\r\nHost: abc.localhost\r\n\r\n")

	// Read back what connector piped from local app
	buf := make([]byte, 1024)
	_ = serverSide.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := serverSide.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	require.Contains(t, string(buf[:n]), "hello")

	_ = serverSide.Close()
	localDone.Wait()
	<-connectorDone
}

func TestHandleAcceptsExpectedStreamType(t *testing.T) {
	for _, typ := range []protocol.StreamType{protocol.StreamTypeHTTP, protocol.StreamTypeTCP} {
		t.Run(string(typ), func(t *testing.T) {
			app := startLocalApp(t, echoUpper)
			serverSide, clientSide := protocol.PipeStream()
			c := New(Options{LocalAddr: app.addr(), ExpectedType: typ})
			done := handleAsync(c, clientSide)

			require.NoError(t, protocol.WriteStreamHeader(serverSide, &protocol.StreamHeader{StreamType: typ}))
			_, err := fmt.Fprint(serverSide, "ping one\n")
			require.NoError(t, err)
			assert.Equal(t, "PING ONE\n", readLine(t, serverSide))

			_ = serverSide.Close()
			require.NoError(t, result(t, done, 5*time.Second))
			assert.Equal(t, 1, app.connections())
		})
	}
}

// --- stream type ------------------------------------------------------------

func TestHandleRejectsStreamOfAnotherType(t *testing.T) {
	cases := []struct{ expected, got protocol.StreamType }{
		{protocol.StreamTypeTCP, protocol.StreamTypeUDP},
		{protocol.StreamTypeTCP, protocol.StreamTypeHTTP},
		{protocol.StreamTypeHTTP, protocol.StreamTypeTCP},
		{protocol.StreamTypeHTTP, protocol.StreamTypeUDP},
		{protocol.StreamTypeUDP, protocol.StreamTypeTCP},
		{protocol.StreamTypeUDP, protocol.StreamTypeHTTP},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("expect %s, get %s", tc.expected, tc.got), func(t *testing.T) {
			app := startLocalApp(t, echoUpper)
			udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			require.NoError(t, err)
			defer udp.Close()

			// The same port number is used for TCP and UDP in the tunnel
			// command, so point the connector at whichever the wrong type
			// would reach.
			localAddr := app.addr()
			if tc.got == protocol.StreamTypeUDP {
				localAddr = udp.LocalAddr().String()
			}
			serverSide, clientSide := protocol.PipeStream()
			c := New(Options{LocalAddr: localAddr, ExpectedType: tc.expected})
			done := handleAsync(c, clientSide)

			require.NoError(t, protocol.WriteStreamHeader(serverSide, &protocol.StreamHeader{StreamType: tc.got, FlowID: 7}))
			go func() {
				// Payload a careless connector would forward.
				_ = protocol.WriteDatagram(serverSide, []byte("must not arrive"))
			}()

			err = result(t, done, 5*time.Second)
			require.ErrorIs(t, err, ErrUnexpectedStreamType)
			expectClosed(t, serverSide)

			assert.Equal(t, 0, app.connections(), "no TCP connection to the local service")
			_ = udp.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, _, readErr := udp.ReadFromUDP(make([]byte, 64))
			var netErr net.Error
			require.ErrorAs(t, readErr, &netErr, "no datagram to the local service")
			assert.True(t, netErr.Timeout())
		})
	}
}

// A type that is not one of the three known ones is refused when the header
// is read (protocol.ReadStreamHeader validates it), whatever the connector
// expects. The error names the problem and never repeats the peer's bytes.
func TestHandleRejectsUnknownStreamType(t *testing.T) {
	unknown := []string{"", "bogus", "TCP", "tcp ", " tcp", "udp\x00", "http\n", "x\x1b[2J\r\nfake"}
	for _, expected := range []protocol.StreamType{protocol.StreamTypeTCP, protocol.StreamTypeHTTP, protocol.StreamTypeUDP} {
		for _, got := range unknown {
			t.Run(fmt.Sprintf("expect %q, get %q", expected, got), func(t *testing.T) {
				app := startLocalApp(t, echoUpper)
				serverSide, clientSide := protocol.PipeStream()
				c := New(Options{LocalAddr: app.addr(), ExpectedType: expected})
				done := handleAsync(c, clientSide)

				require.NoError(t, protocol.WriteStreamHeader(serverSide, &protocol.StreamHeader{StreamType: protocol.StreamType(got)}))

				err := result(t, done, 5*time.Second)
				require.ErrorIs(t, err, protocol.ErrInvalidStreamHeader)
				assertASCIIPrintable(t, err.Error())
				assert.Less(t, len(err.Error()), 200)
				if got != "" {
					assert.NotContains(t, err.Error(), got, "the error must not repeat the peer's value")
				}
				expectClosed(t, serverSide)
				assert.Equal(t, 0, app.connections(), "an unknown type must never be treated as TCP")
			})
		}
	}
}

// A connector that was not told which type to expect serves nothing, not
// even the three known types, and does not wait for a header to say so.
func TestHandleWithoutExpectedTypeRefusesEveryStream(t *testing.T) {
	for _, got := range []protocol.StreamType{protocol.StreamTypeHTTP, protocol.StreamTypeTCP, protocol.StreamTypeUDP, "bogus"} {
		t.Run(string(got), func(t *testing.T) {
			app := startLocalApp(t, echoUpper)
			serverSide, clientSide := protocol.PipeStream()
			c := New(Options{LocalAddr: app.addr(), HeaderTimeout: time.Minute})
			done := handleAsync(c, clientSide)
			go func() {
				_ = protocol.WriteStreamHeader(serverSide, &protocol.StreamHeader{StreamType: got, FlowID: 7})
			}()

			require.ErrorIs(t, result(t, done, 5*time.Second), ErrExpectedTypeNotSet)
			expectClosed(t, serverSide)
			assert.Equal(t, 0, app.connections())
		})
	}

	// No header at all: the refusal does not depend on one.
	_, clientSide := protocol.PipeStream()
	c := New(Options{LocalAddr: "127.0.0.1:1", HeaderTimeout: time.Minute})
	require.ErrorIs(t, result(t, handleAsync(c, clientSide), 5*time.Second), ErrExpectedTypeNotSet)
}

// The type comes from the wire and may be up to a header long; none of it
// ends up in the error.
func TestHandleUnknownTypeErrorDoesNotRepeatTheType(t *testing.T) {
	for _, expected := range []protocol.StreamType{protocol.StreamTypeUDP, protocol.StreamTypeTCP} {
		serverSide, clientSide := protocol.PipeStream()
		c := New(Options{LocalAddr: "127.0.0.1:1", ExpectedType: expected})
		done := handleAsync(c, clientSide)

		long := protocol.StreamType(strings.Repeat("A", 3000))
		require.NoError(t, protocol.WriteStreamHeader(serverSide, &protocol.StreamHeader{StreamType: long}))

		err := result(t, done, 5*time.Second)
		require.ErrorIs(t, err, protocol.ErrInvalidStreamHeader)
		assert.Equal(t, 0, strings.Count(err.Error(), "A"), "expected type %q", expected)
		assert.Less(t, len(err.Error()), 200)
	}
}

// The connector's own type check is a second line of defence behind the
// header validation of the protocol package. It is tested directly, because
// through Handle an unknown type no longer reaches it.
func TestCheckStreamTypeIsItsOwnLineOfDefence(t *testing.T) {
	tcp := New(Options{ExpectedType: protocol.StreamTypeTCP})
	require.NoError(t, tcp.checkStreamType(protocol.StreamTypeTCP))
	require.ErrorIs(t, tcp.checkStreamType(protocol.StreamTypeUDP), ErrUnexpectedStreamType)
	require.ErrorIs(t, tcp.checkStreamType(protocol.StreamTypeHTTP), ErrUnexpectedStreamType)
	require.ErrorIs(t, tcp.checkStreamType("bogus"), ErrUnexpectedStreamType)
	require.ErrorIs(t, tcp.checkStreamType(""), ErrUnexpectedStreamType)

	// Equal to the expected type is not enough: the type must also be one
	// the connector can serve.
	quic := New(Options{ExpectedType: "quic"})
	require.ErrorIs(t, quic.checkStreamType("quic"), ErrUnexpectedStreamType)

	// What it puts into the error is cut to 32 bytes and quoted.
	err := tcp.checkStreamType(protocol.StreamType(strings.Repeat("A", 3000)))
	require.ErrorIs(t, err, ErrUnexpectedStreamType)
	assert.Equal(t, 32, strings.Count(err.Error(), "A"))
	err = tcp.checkStreamType("x\x1b[2J\r\nfake")
	require.ErrorIs(t, err, ErrUnexpectedStreamType)
	assertASCIIPrintable(t, err.Error())
}

// With two stream_type keys the JSON decoder keeps the last one; the type
// that is checked is the type that is used.
func TestHandleChecksTheStreamTypeItUses(t *testing.T) {
	app := startLocalApp(t, echoUpper)
	serverSide, clientSide := protocol.PipeStream()
	c := New(Options{LocalAddr: app.addr(), ExpectedType: protocol.StreamTypeTCP})
	done := handleAsync(c, clientSide)

	require.NoError(t, protocol.WriteFrame(serverSide, []byte(`{"stream_type":"tcp","stream_type":"udp"}`)))

	require.ErrorIs(t, result(t, done, 5*time.Second), ErrUnexpectedStreamType)
	assert.Equal(t, 0, app.connections())
}

// A connector whose expected type is not a known type accepts nothing.
func TestHandleWithUnknownExpectedTypeRejectsEverything(t *testing.T) {
	cases := []struct {
		got  protocol.StreamType
		want error
	}{
		// the header validation refuses a type nobody knows ...
		{"quic", protocol.ErrInvalidStreamHeader},
		// ... and the connector refuses a known type it was not set up for
		{protocol.StreamTypeTCP, ErrUnexpectedStreamType},
	}
	for _, tc := range cases {
		app := startLocalApp(t, echoUpper)
		serverSide, clientSide := protocol.PipeStream()
		c := New(Options{LocalAddr: app.addr(), ExpectedType: "quic"})
		done := handleAsync(c, clientSide)

		require.NoError(t, protocol.WriteStreamHeader(serverSide, &protocol.StreamHeader{StreamType: tc.got}))
		require.ErrorIs(t, result(t, done, 5*time.Second), tc.want, "stream type %q", tc.got)
		expectClosed(t, serverSide)
		assert.Equal(t, 0, app.connections())
	}
}

// --- header deadline --------------------------------------------------------

func TestHandleHeaderTimeout(t *testing.T) {
	t.Run("no header at all", func(t *testing.T) {
		app := startLocalApp(t, echoUpper)
		serverSide, clientSide := protocol.PipeStream()
		c := New(Options{LocalAddr: app.addr(), ExpectedType: protocol.StreamTypeTCP, HeaderTimeout: 300 * time.Millisecond})

		start := time.Now()
		err := result(t, handleAsync(c, clientSide), 10*time.Second)
		require.ErrorIs(t, err, ErrHeaderTimeout)
		assert.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
		expectClosed(t, serverSide)
		assert.Equal(t, 0, app.connections())
	})

	t.Run("header that stops half way", func(t *testing.T) {
		serverSide, clientSide := protocol.PipeStream()
		c := New(Options{LocalAddr: "127.0.0.1:1", ExpectedType: protocol.StreamTypeTCP, HeaderTimeout: 300 * time.Millisecond})
		done := handleAsync(c, clientSide)

		_, err := serverSide.Write([]byte{0, 0}) // two of the four length bytes
		require.NoError(t, err)
		require.ErrorIs(t, result(t, done, 10*time.Second), ErrHeaderTimeout)
	})

	t.Run("stream without deadline support", func(t *testing.T) {
		serverSide, clientSide := protocol.PipeStream()
		// Hide SetReadDeadline: the timeout has to work regardless.
		plain := struct{ io.ReadWriteCloser }{clientSide}
		c := New(Options{LocalAddr: "127.0.0.1:1", ExpectedType: protocol.StreamTypeTCP, HeaderTimeout: 300 * time.Millisecond})

		start := time.Now()
		err := result(t, handleAsync(c, plain), 10*time.Second)
		require.ErrorIs(t, err, ErrHeaderTimeout)
		assert.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
		expectClosed(t, serverSide)
	})
}

// A header that arrives in pieces but in time is fine, and the header
// deadline does not apply to the data that follows.
func TestHandleHeaderDeadlineCoversOnlyTheHeader(t *testing.T) {
	app := startLocalApp(t, echoUpper)
	serverSide, clientSide := protocol.PipeStream()
	c := New(Options{LocalAddr: app.addr(), ExpectedType: protocol.StreamTypeTCP, HeaderTimeout: time.Second})
	done := handleAsync(c, clientSide)

	frame := []byte(`{"stream_type":"tcp"}`)
	wire := append([]byte{0, 0, 0, byte(len(frame))}, frame...)
	for _, part := range [][]byte{wire[:2], wire[2:9], wire[9:]} {
		_, err := serverSide.Write(part)
		require.NoError(t, err)
		time.Sleep(20 * time.Millisecond)
	}

	// Stay silent for longer than the header timeout, then send data.
	stillRunning(t, done, 1300*time.Millisecond)
	_, err := fmt.Fprint(serverSide, "after the pause\n")
	require.NoError(t, err)
	assert.Equal(t, "AFTER THE PAUSE\n", readLine(t, serverSide))

	_ = serverSide.Close()
	require.NoError(t, result(t, done, 5*time.Second))
}

func TestHandleHeaderTimeoutDisabledByNegativeValue(t *testing.T) {
	serverSide, clientSide := protocol.PipeStream()
	c := New(Options{LocalAddr: "127.0.0.1:1", ExpectedType: protocol.StreamTypeTCP, HeaderTimeout: -1})
	done := handleAsync(c, clientSide)

	stillRunning(t, done, 700*time.Millisecond)
	_ = serverSide.Close()
	err := result(t, done, 5*time.Second)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrHeaderTimeout)
}

// --- concurrency limit ------------------------------------------------------

func TestOptionDefaults(t *testing.T) {
	c := New(Options{})
	assert.Equal(t, 1024, c.opts.MaxStreams)
	assert.Equal(t, 10*time.Second, c.opts.HeaderTimeout)
	assert.Equal(t, 5*time.Minute, c.opts.UDPIdleTimeout)
	assert.Equal(t, 5*time.Second, c.opts.DialTimeout)
	assert.Equal(t, 1024, cap(c.slots))

	custom := New(Options{MaxStreams: 3, HeaderTimeout: time.Second, UDPIdleTimeout: 2 * time.Second, DialTimeout: 4 * time.Second})
	assert.Equal(t, 3, cap(custom.slots))
	assert.Equal(t, time.Second, custom.opts.HeaderTimeout)
	assert.Equal(t, 2*time.Second, custom.opts.UDPIdleTimeout)
	assert.Equal(t, 4*time.Second, custom.opts.DialTimeout)

	unlimited := New(Options{MaxStreams: -1})
	assert.Nil(t, unlimited.slots)
}

// The default limit is 1024 streams at a time: stream 1025 is refused while
// 1024 are open, and accepted again once one of them is gone.
func TestHandleLimitsConcurrentStreamsByDefault(t *testing.T) {
	app := startLocalApp(t, echoUpper)
	c := New(Options{LocalAddr: app.addr(), ExpectedType: protocol.StreamTypeTCP, HeaderTimeout: time.Minute})

	const limit = 1024
	type parked struct {
		serverSide protocol.Stream
		done       <-chan error
	}
	open := make([]parked, 0, limit)
	for i := 0; i < limit; i++ {
		serverSide, clientSide := protocol.PipeStream()
		open = append(open, parked{serverSide, handleAsync(c, clientSide)})
	}
	t.Cleanup(func() {
		for _, p := range open {
			_ = p.serverSide.Close()
		}
	})
	// All 1024 hold a slot (they wait for their header).
	require.Eventually(t, func() bool { return len(c.slots) == limit }, 10*time.Second, 10*time.Millisecond)

	serverSide, clientSide := protocol.PipeStream()
	err := result(t, handleAsync(c, clientSide), 5*time.Second)
	require.ErrorIs(t, err, ErrTooManyStreams)
	expectClosed(t, serverSide)

	// One stream ends: its slot is free again and a new stream works.
	_ = open[0].serverSide.Close()
	require.Error(t, result(t, open[0].done, 5*time.Second))

	serverSide, clientSide = protocol.PipeStream()
	done := handleAsync(c, clientSide)
	require.NoError(t, protocol.WriteStreamHeader(serverSide, &protocol.StreamHeader{StreamType: protocol.StreamTypeTCP}))
	_, err = fmt.Fprint(serverSide, "slot reused\n")
	require.NoError(t, err)
	assert.Equal(t, "SLOT REUSED\n", readLine(t, serverSide))
	_ = serverSide.Close()
	require.NoError(t, result(t, done, 5*time.Second))
}

func TestHandleLimitIsConfigurable(t *testing.T) {
	c := New(Options{LocalAddr: "127.0.0.1:1", ExpectedType: protocol.StreamTypeTCP, MaxStreams: 2, HeaderTimeout: time.Minute})

	s1, c1 := protocol.PipeStream()
	s2, c2 := protocol.PipeStream()
	defer s1.Close()
	defer s2.Close()
	handleAsync(c, c1)
	handleAsync(c, c2)
	require.Eventually(t, func() bool { return len(c.slots) == 2 }, 5*time.Second, 5*time.Millisecond)

	_, c3 := protocol.PipeStream()
	require.ErrorIs(t, result(t, handleAsync(c, c3), 5*time.Second), ErrTooManyStreams)
}

func TestHandleWithoutLimitAcceptsMoreThanTheDefault(t *testing.T) {
	c := New(Options{LocalAddr: "127.0.0.1:1", ExpectedType: protocol.StreamTypeTCP, MaxStreams: -1, HeaderTimeout: time.Minute})

	var dones []<-chan error
	for i := 0; i < 1030; i++ {
		serverSide, clientSide := protocol.PipeStream()
		t.Cleanup(func() { _ = serverSide.Close() })
		dones = append(dones, handleAsync(c, clientSide))
	}
	time.Sleep(300 * time.Millisecond)
	for _, done := range dones {
		select {
		case err := <-done:
			t.Fatalf("a stream was turned away: %v", err)
		default:
		}
	}
}

// A slot is given back on every way out of Handle, not only on success.
func TestHandleReleasesSlotOnFailure(t *testing.T) {
	// Nothing listens on the local port: every stream fails at the dial.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := ln.Addr().String()
	require.NoError(t, ln.Close())

	c := New(Options{LocalAddr: closedAddr, ExpectedType: protocol.StreamTypeTCP, MaxStreams: 1, HeaderTimeout: 200 * time.Millisecond, DialTimeout: 2 * time.Second})

	for i := 0; i < 3; i++ {
		serverSide, clientSide := protocol.PipeStream()
		done := handleAsync(c, clientSide)
		require.NoError(t, protocol.WriteStreamHeader(serverSide, &protocol.StreamHeader{StreamType: protocol.StreamTypeTCP}))
		err := result(t, done, 10*time.Second)
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrTooManyStreams, "attempt %d: the slot of the failed stream was not released", i)
		expectClosed(t, serverSide)
	}

	// Same for a stream that never sends its header, one with an unknown
	// type and one with a known type that is not the expected one.
	_, clientSide := protocol.PipeStream()
	require.ErrorIs(t, result(t, handleAsync(c, clientSide), 10*time.Second), ErrHeaderTimeout)

	serverSide, clientSide := protocol.PipeStream()
	done := handleAsync(c, clientSide)
	require.NoError(t, protocol.WriteStreamHeader(serverSide, &protocol.StreamHeader{StreamType: "bogus"}))
	require.ErrorIs(t, result(t, done, 10*time.Second), protocol.ErrInvalidStreamHeader)

	serverSide, clientSide = protocol.PipeStream()
	done = handleAsync(c, clientSide)
	require.NoError(t, protocol.WriteStreamHeader(serverSide, &protocol.StreamHeader{StreamType: protocol.StreamTypeUDP}))
	require.ErrorIs(t, result(t, done, 10*time.Second), ErrUnexpectedStreamType)

	assert.Equal(t, 0, len(c.slots))
}

// --- local side ends --------------------------------------------------------

// When the local service is done and closes its connection, the connector
// closes the stream instead of waiting for the server to do it.
func TestHandleClosesStreamWhenLocalSideEnds(t *testing.T) {
	app := startLocalApp(t, func(conn net.Conn) {
		_, _ = bufio.NewReader(conn).ReadString('\n')
		fmt.Fprint(conn, "bye\n")
		// returning closes the connection
	})
	serverSide, clientSide := protocol.PipeStream()
	c := New(Options{LocalAddr: app.addr(), ExpectedType: protocol.StreamTypeTCP})
	done := handleAsync(c, clientSide)

	require.NoError(t, protocol.WriteStreamHeader(serverSide, &protocol.StreamHeader{StreamType: protocol.StreamTypeTCP}))
	_, err := fmt.Fprint(serverSide, "hello\n")
	require.NoError(t, err)

	// The server side keeps its end open the whole time.
	setReadDeadline(t, serverSide, 5*time.Second)
	got, err := io.ReadAll(serverSide)
	require.NoError(t, err, "the stream must end with EOF, not with the read deadline")
	assert.Equal(t, "bye\n", string(got))
	require.NoError(t, result(t, done, 5*time.Second))
}

func TestHandleLocalDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := ln.Addr().String()
	require.NoError(t, ln.Close())

	serverSide, clientSide := protocol.PipeStream()
	c := New(Options{LocalAddr: closedAddr, ExpectedType: protocol.StreamTypeHTTP})
	done := handleAsync(c, clientSide)
	require.NoError(t, protocol.WriteStreamHeader(serverSide, &protocol.StreamHeader{StreamType: protocol.StreamTypeHTTP}))

	err = result(t, done, 10*time.Second)
	require.Error(t, err)
	var opErr *net.OpError
	require.True(t, errors.As(err, &opErr), "want the dial error, got %v", err)
	expectClosed(t, serverSide)
}
