package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// --- version ----------------------------------------------------------------

func setBuildInfo(t *testing.T, v, c, d string) {
	t.Helper()
	oldV, oldC, oldD := version, commit, date
	version, commit, date = v, c, d
	t.Cleanup(func() { version, commit, date = oldV, oldC, oldD })
}

func runCommand(t *testing.T, ctx context.Context, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err = cmd.ExecuteContext(ctx)
	return out.String(), errOut.String(), err
}

func TestVersionCommandPrintsBuildInfo(t *testing.T) {
	setBuildInfo(t, "1.2.3", "abc1234", "2026-11-14T10:00:00Z")

	stdout, _, err := runCommand(t, context.Background(), "version")
	require.NoError(t, err)
	assert.Equal(t, "tunnel 1.2.3 (commit abc1234, built 2026-11-14T10:00:00Z)\n", stdout)
}

func TestVersionDefaultsForLocalBuilds(t *testing.T) {
	// Not overridden by -ldflags in a test binary.
	assert.Equal(t, "dev", version)
	assert.Equal(t, "none", commit)
	assert.Equal(t, "unknown", date)
}

// --- final error ------------------------------------------------------------

// The final error can quote text chosen by the peer (a TLS verification error
// lists the names in the peer's certificate). It must reach the terminal
// without escape sequences, bidirectional controls and line breaks.
func TestPrintErrorCleansPeerText(t *testing.T) {
	const esc = "\x1b"
	bidi := string(rune(0x202e)) // RIGHT-TO-LEFT OVERRIDE
	err := fmt.Errorf("connect to tunnel.example.org:7443: %w", errors.New(
		"tls: failed to verify certificate: x509: certificate is valid for evil"+esc+"[2J"+esc+"[31m.example"+bidi+
			", not tunnel.example.org\nerror: everything is fine\r"))

	var out bytes.Buffer
	printError(&out, err)

	assert.Equal(t,
		"error: connect to tunnel.example.org:7443: tls: failed to verify certificate: x509: certificate is valid for "+
			"evil[2J[31m.example, not tunnel.example.orgerror: everything is fine\n",
		out.String())
	assert.Equal(t, 1, strings.Count(out.String(), "\n"), "exactly one line")
}

func TestPrintErrorCutsLongText(t *testing.T) {
	var out bytes.Buffer
	printError(&out, errors.New(strings.Repeat("a", 3000)))

	assert.Equal(t, "error: "+strings.Repeat("a", 2048)+"...\n", out.String())

	out.Reset()
	printError(&out, errors.New(strings.Repeat("a", 2048)))
	assert.Equal(t, "error: "+strings.Repeat("a", 2048)+"\n", out.String())
}

// --- a scripted tunnel server ----------------------------------------------

type fakeServer struct {
	addr   string
	caFile string

	mu     sync.Mutex
	hellos []protocol.Hello
}

func (f *fakeServer) lastHello() (protocol.Hello, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hellos) == 0 {
		return protocol.Hello{}, false
	}
	return f.hellos[len(f.hellos)-1], true
}

func readEnvelope(r io.Reader) (protocol.Envelope, error) {
	var env protocol.Envelope
	raw, err := protocol.ReadFrame(r, 1<<20)
	if err != nil {
		return env, err
	}
	return env, json.Unmarshal(raw, &env)
}

func writeEnvelope(w io.Writer, typ protocol.MessageType, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(protocol.Envelope{Type: typ, Payload: body})
	if err != nil {
		return err
	}
	return protocol.WriteFrame(w, raw)
}

// startFakeServer runs a TLS + yamux server with a certificate from a private
// CA. After the hello it answers one register request with registerAck and
// then hands the session to drive, which opens data streams.
func startFakeServer(t *testing.T, wantRegister, ackType protocol.MessageType, registerAck any, drive func(sess protocol.Session)) *fakeServer {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cmd test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "cmd test server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600))

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	f := &fakeServer{addr: ln.Addr().String(), caFile: caFile}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				sess, err := protocol.NewServerSession(conn)
				if err != nil {
					return
				}
				defer sess.Close()
				ctrl, err := sess.AcceptStream()
				if err != nil {
					return
				}
				env, err := readEnvelope(ctrl)
				if err != nil || env.Type != protocol.TypeHello {
					return
				}
				var hello protocol.Hello
				if json.Unmarshal(env.Payload, &hello) != nil {
					return
				}
				f.mu.Lock()
				f.hellos = append(f.hellos, hello)
				f.mu.Unlock()
				if writeEnvelope(ctrl, protocol.TypeHelloAck, protocol.HelloAck{SessionID: "sess-cmd"}) != nil {
					return
				}
				env, err = readEnvelope(ctrl)
				if err != nil || env.Type != wantRegister {
					return
				}
				if writeEnvelope(ctrl, ackType, registerAck) != nil {
					return
				}
				drive(sess)
			}()
		}
	}()
	return f
}

func writeClientConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tunnel.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// startUpperEcho is the local TCP service: it answers each line in upper case.
func startUpperEcho(t *testing.T) (port int, connections func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return ln.Addr().(*net.TCPAddr).Port, serveUpperEcho(t, ln)
}

func serveUpperEcho(t *testing.T, ln net.Listener) (connections func() int) {
	t.Helper()
	t.Cleanup(func() { _ = ln.Close() })
	var (
		mu sync.Mutex
		n  int
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			n++
			mu.Unlock()
			go func() {
				defer conn.Close()
				sc := bufio.NewScanner(conn)
				for sc.Scan() {
					fmt.Fprintf(conn, "%s\n", strings.ToUpper(sc.Text()))
				}
			}()
		}
	}()
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// startLocalServices starts the TCP and the UDP service on the same port
// number. `tunnel tcp 8080` and `tunnel udp 8080` name a local port, not a
// protocol, so a stream of the wrong type would reach whatever listens on
// that number with the other protocol. With both present, such a mix-up is
// visible in the counters.
func startLocalServices(t *testing.T) (port int, tcpConnections, udpReceived func() int) {
	t.Helper()
	// The number is drawn from 20000-39999 instead of letting the system
	// pick one: Windows reserves parts of its dynamic port range per
	// protocol, so a number it hands out for TCP is often refused for UDP.
	for attempt := 0; attempt < 200; attempt++ {
		port = 20000 + mathrand.IntN(20000)
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
		if err != nil {
			_ = ln.Close()
			continue
		}
		return port, serveUpperEcho(t, ln), serveUDPUpperEcho(t, conn)
	}
	t.Fatal("found no port number that is free for TCP and UDP")
	return 0, nil, nil
}

// serveUDPUpperEcho is the local UDP service: it answers each datagram in
// upper case; received counts the datagrams it got.
func serveUDPUpperEcho(t *testing.T, conn *net.UDPConn) (received func() int) {
	t.Helper()
	t.Cleanup(func() { _ = conn.Close() })
	var (
		mu sync.Mutex
		n  int
	)
	go func() {
		buf := make([]byte, 4096)
		for {
			size, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			n++
			mu.Unlock()
			_, _ = conn.WriteToUDP([]byte(strings.ToUpper(string(buf[:size]))), addr)
		}
	}()
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

type deadlineStream interface {
	protocol.Stream
	SetReadDeadline(time.Time) error
}

// openStream opens a data stream towards the client and writes its header.
func openStream(sess protocol.Session, typ protocol.StreamType) (deadlineStream, error) {
	s, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteStreamHeader(s, &protocol.StreamHeader{StreamType: typ, FlowID: 1}); err != nil {
		return nil, err
	}
	return s.(deadlineStream), nil
}

// closedByClient reports whether the client closed the stream (EOF) within
// five seconds without sending anything.
func closedByClient(s deadlineStream) error {
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := s.Read(make([]byte, 16))
	if err == io.EOF && n == 0 {
		return nil
	}
	return fmt.Errorf("stream was not closed by the client: n=%d err=%v", n, err)
}

// --- the tunnel commands end to end ------------------------------------------

// Each command only serves streams of its own type: a stream of another type
// is closed without touching the local port, a stream of the right type is
// piped. The server certificate comes from a private CA that the client only
// knows through ca_file in its config.
func TestTunnelCommandsServeOnlyTheirOwnStreamType(t *testing.T) {
	setBuildInfo(t, "7.8.9", "abc1234", "2026-11-14T10:00:00Z")

	cases := []struct {
		command      string
		wantRegister protocol.MessageType
		ackType      protocol.MessageType
		ack          any
		ownType      protocol.StreamType
		otherTypes   []protocol.StreamType
		wantStatus   string
	}{
		{
			command: "http", wantRegister: protocol.TypeRegisterHTTP, ackType: protocol.TypeRegisterHTTPAck,
			ack:     protocol.RegisterHTTPAck{PublicURL: "https://app.example.org\x1b[2J\r\n", Subdomain: "app"},
			ownType: protocol.StreamTypeHTTP, otherTypes: []protocol.StreamType{protocol.StreamTypeTCP, protocol.StreamTypeUDP, "bogus"},
			wantStatus: "https://app.example.org[2J",
		},
		{
			command: "tcp", wantRegister: protocol.TypeRegisterTCP, ackType: protocol.TypeRegisterTCPAck,
			ack:     protocol.RegisterTCPAck{PublicAddr: "example.org:15042\x1b[2J\r\n", Port: 15042},
			ownType: protocol.StreamTypeTCP, otherTypes: []protocol.StreamType{protocol.StreamTypeHTTP, protocol.StreamTypeUDP, "bogus"},
			wantStatus: "example.org:15042[2J",
		},
		{
			command: "udp", wantRegister: protocol.TypeRegisterUDP, ackType: protocol.TypeRegisterUDPAck,
			ack:     protocol.RegisterUDPAck{PublicAddr: "example.org:35000\x1b[2J\r\n", Port: 35000},
			ownType: protocol.StreamTypeUDP, otherTypes: []protocol.StreamType{protocol.StreamTypeHTTP, protocol.StreamTypeTCP, "bogus"},
			wantStatus: "example.org:35000[2J",
		},
	}

	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			localPort, tcpConnections, udpReceived := startLocalServices(t)

			driven := make(chan error, 1)
			srv := startFakeServer(t, tc.wantRegister, tc.ackType, tc.ack, func(sess protocol.Session) {
				driven <- func() error {
					// Streams of every other type are closed by the client.
					for _, other := range tc.otherTypes {
						s, err := openStream(sess, other)
						if err != nil {
							return err
						}
						go func() { _ = protocol.WriteDatagram(s, []byte("wrong type")) }()
						if err := closedByClient(s); err != nil {
							return fmt.Errorf("type %q: %w", other, err)
						}
					}
					// The command's own type is served.
					s, err := openStream(sess, tc.ownType)
					if err != nil {
						return err
					}
					defer s.Close()
					_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
					if tc.ownType == protocol.StreamTypeUDP {
						if err := protocol.WriteDatagram(s, []byte("ping udp")); err != nil {
							return err
						}
						got, err := protocol.ReadDatagram(s, make([]byte, 64))
						if err != nil || string(got) != "PING UDP" {
							return fmt.Errorf("udp round trip: %q, %v", got, err)
						}
						return nil
					}
					if _, err := fmt.Fprint(s, "ping tcp\n"); err != nil {
						return err
					}
					line, err := bufio.NewReader(s).ReadString('\n')
					if err != nil || line != "PING TCP\n" {
						return fmt.Errorf("tcp round trip: %q, %v", line, err)
					}
					return nil
				}()
				// Keep the session open until the client leaves. Returning here
				// would close it, and the command would end with "accept
				// stream" before the test gets to stop it.
				_, _ = sess.AcceptStream()
			})

			cfgPath := writeClientConfig(t, fmt.Sprintf("server: %s\ntoken: twbl_cmd_token\nca_file: '%s'\n", srv.addr, srv.caFile))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			type cmdResult struct {
				stdout, stderr string
				err            error
			}
			finished := make(chan cmdResult, 1)
			go func() {
				stdout, stderr, err := runCommand(t, ctx, tc.command, strconv.Itoa(localPort), "--config", cfgPath)
				finished <- cmdResult{stdout, stderr, err}
			}()

			select {
			case err := <-driven:
				require.NoError(t, err)
			case res := <-finished:
				t.Fatalf("command ended early: err=%v stderr=%q", res.err, res.stderr)
			case <-time.After(20 * time.Second):
				t.Fatal("server script did not finish")
			}

			// Only the stream of the command's own type reached a local port.
			if tc.ownType == protocol.StreamTypeUDP {
				assert.Equal(t, 0, tcpConnections())
				assert.Equal(t, 1, udpReceived())
			} else {
				assert.Equal(t, 1, tcpConnections())
				assert.Equal(t, 0, udpReceived())
			}

			cancel()
			var res cmdResult
			select {
			case res = <-finished:
			case <-time.After(10 * time.Second):
				t.Fatal("command did not stop after its context was cancelled")
			}
			require.NoError(t, res.err)

			// The status line shows the server's text without control characters.
			assert.Contains(t, res.stdout, tc.wantStatus)
			assert.NotContains(t, res.stdout, "\x1b")
			assert.NotContains(t, res.stdout, "\r")
			assert.Contains(t, res.stdout, "127.0.0.1:"+strconv.Itoa(localPort))
			// Verification is on: no warning.
			assert.NotContains(t, res.stderr, "warning:")

			hello, ok := srv.lastHello()
			require.True(t, ok)
			assert.Equal(t, "twbl_cmd_token", hello.Token)
			assert.Equal(t, "7.8.9", hello.ClientVersion)
		})
	}
}

func TestTunnelCommandWarnsWhenVerificationIsOff(t *testing.T) {
	tcpPort, _ := startUpperEcho(t)
	driven := make(chan error, 1)
	srv := startFakeServer(t, protocol.TypeRegisterHTTP, protocol.TypeRegisterHTTPAck,
		protocol.RegisterHTTPAck{PublicURL: "https://app.example.org", Subdomain: "app"},
		func(sess protocol.Session) {
			// One round trip proves that the client is up and serving before
			// the test stops it.
			driven <- func() error {
				s, err := openStream(sess, protocol.StreamTypeHTTP)
				if err != nil {
					return err
				}
				defer s.Close()
				_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := fmt.Fprint(s, "ping\n"); err != nil {
					return err
				}
				line, err := bufio.NewReader(s).ReadString('\n')
				if err != nil || line != "PING\n" {
					return fmt.Errorf("round trip: %q, %v", line, err)
				}
				return nil
			}()
			// keep the session until the client leaves
			_, _ = sess.AcceptStream()
		})

	// No ca_file: the private CA is unknown, only insecure_skip_verify lets
	// the client connect.
	cfgPath := writeClientConfig(t, fmt.Sprintf("server: %s\ntoken: twbl_cmd_token\ninsecure_skip_verify: true\n", srv.addr))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type cmdResult struct {
		stderr string
		err    error
	}
	finished := make(chan cmdResult, 1)
	go func() {
		_, stderr, err := runCommand(t, ctx, "http", strconv.Itoa(tcpPort), "--config", cfgPath)
		finished <- cmdResult{stderr, err}
	}()

	select {
	case err := <-driven:
		require.NoError(t, err)
	case res := <-finished:
		t.Fatalf("command ended early: err=%v stderr=%q", res.err, res.stderr)
	case <-time.After(20 * time.Second):
		t.Fatal("client never registered")
	}
	cancel()
	res := <-finished
	require.NoError(t, res.err)

	lines := strings.Split(strings.TrimSpace(res.stderr), "\n")
	var warnings []string
	for _, line := range lines {
		if strings.HasPrefix(line, "warning: ") {
			warnings = append(warnings, line)
		}
	}
	require.Len(t, warnings, 1, "stderr: %q", res.stderr)
	assert.Contains(t, warnings[0], "insecure_skip_verify")
	assert.NotContains(t, res.stderr, "twbl_cmd_token")
}

func TestTunnelCommandRefusesUnknownCAWithoutCAFile(t *testing.T) {
	tcpPort, connections := startUpperEcho(t)
	srv := startFakeServer(t, protocol.TypeRegisterHTTP, protocol.TypeRegisterHTTPAck,
		protocol.RegisterHTTPAck{PublicURL: "https://app.example.org"}, func(protocol.Session) {})

	cfgPath := writeClientConfig(t, fmt.Sprintf("server: %s\ntoken: twbl_cmd_token\n", srv.addr))
	_, stderr, err := runCommand(t, context.Background(), "http", strconv.Itoa(tcpPort), "--config", cfgPath)
	var unknown x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknown)
	// The command itself prints no error text; that is left to main, which
	// cleans it first (printError).
	assert.NotContains(t, stderr, "x509")
	assert.NotContains(t, stderr, "certificate")
	_, sawHello := srv.lastHello()
	assert.False(t, sawHello, "the token must not be sent to a server that failed verification")
	assert.Equal(t, 0, connections())
}
