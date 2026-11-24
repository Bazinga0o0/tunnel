package dialer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// --- test PKI ---------------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// writeFile stores the CA certificate as a PEM file and returns its path.
func (ca *testCA) writeFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, ca.pem, 0o600))
	return path
}

// issue returns a server certificate signed by the CA.
func (ca *testCA) issue(t *testing.T, dnsNames []string, ips []net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "tunnel test server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func loopbackCert(t *testing.T, ca *testCA) tls.Certificate {
	t.Helper()
	return ca.issue(t, nil, []net.IP{net.ParseIP("127.0.0.1")})
}

// --- fake server ------------------------------------------------------------

// startFakeServer runs a TLS + yamux server whose control stream is driven by
// script. The connection stays open until script returns.
func startFakeServer(t *testing.T, cert tls.Certificate, script func(ctrl protocol.Stream)) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				mux, err := protocol.NewServerSession(conn)
				if err != nil {
					return
				}
				defer mux.Close()
				ctrl, err := mux.AcceptStream()
				if err != nil {
					return
				}
				script(ctrl)
			}()
		}
	}()
	return ln.Addr().String()
}

// untilTestEnds returns a function that blocks until the test is over.
func untilTestEnds(t *testing.T) func() {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	return func() { <-done }
}

func readRequest(ctrl protocol.Stream) (protocol.MessageType, error) {
	raw, err := protocol.ReadFrame(ctrl, 1<<20)
	if err != nil {
		return "", err
	}
	var env protocol.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", err
	}
	return env.Type, nil
}

func writeReply(ctrl protocol.Stream, typ protocol.MessageType, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(protocol.Envelope{Type: typ, Payload: body})
	if err != nil {
		return err
	}
	return protocol.WriteFrame(ctrl, raw)
}

// ackHello reads the hello and answers with a successful hello_ack.
func ackHello(ctrl protocol.Stream, sessionID string) bool {
	if typ, err := readRequest(ctrl); err != nil || typ != protocol.TypeHello {
		return false
	}
	return writeReply(ctrl, protocol.TypeHelloAck, protocol.HelloAck{SessionID: sessionID}) == nil
}

// within fails the test if fn does not return inside limit and reports how
// long fn took.
func within(t *testing.T, limit time.Duration, fn func()) time.Duration {
	t.Helper()
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return time.Since(start)
	case <-time.After(limit):
		t.Fatalf("did not return within %s", limit)
		return 0
	}
}

func assertPrintable(t *testing.T, s string) {
	t.Helper()
	assert.True(t, utf8.ValidString(s), "not valid UTF-8: %q", s)
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x202e || r == 0x200b || r == 0xfeff {
			t.Errorf("non-printable rune %U in %q", r, s)
		}
	}
}

// --- ca_file ----------------------------------------------------------------

func TestDialTrustsServerSignedByCAFile(t *testing.T) {
	ca := newTestCA(t, "private test CA")
	wait := untilTestEnds(t)
	addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
		if ackHello(ctrl, "sess-private-ca") {
			wait()
		}
	})

	d := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: ca.writeFile(t)})
	sess, err := d.Dial(context.Background())
	require.NoError(t, err)
	defer sess.Close()
	assert.Equal(t, "sess-private-ca", sess.SessionID())
}

func TestDialWithoutCAFileRejectsPrivateCA(t *testing.T) {
	ca := newTestCA(t, "private test CA")
	addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
		ackHello(ctrl, "must-not-be-reached")
	})

	d := New(Options{ServerAddr: addr, Token: "twbl_x"})
	_, err := d.Dial(context.Background())
	var unknown x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknown)
}

func TestDialRejectsServerSignedByAnotherCA(t *testing.T) {
	serverCA := newTestCA(t, "CA of the server")
	otherCA := newTestCA(t, "CA in ca_file")
	addr := startFakeServer(t, loopbackCert(t, serverCA), func(ctrl protocol.Stream) {
		ackHello(ctrl, "must-not-be-reached")
	})

	d := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: otherCA.writeFile(t)})
	_, err := d.Dial(context.Background())
	var unknown x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknown)
}

// ca_file replaces the trust anchor, it does not switch the host name check off.
func TestDialWithCAFileStillChecksHostName(t *testing.T) {
	ca := newTestCA(t, "private test CA")
	cert := ca.issue(t, []string{"other-host.example"}, nil)
	addr := startFakeServer(t, cert, func(ctrl protocol.Stream) {
		ackHello(ctrl, "must-not-be-reached")
	})

	d := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: ca.writeFile(t)})
	_, err := d.Dial(context.Background())
	var hostErr x509.HostnameError
	require.ErrorAs(t, err, &hostErr)
}

func TestDialFailsClosedOnUnusableCAFile(t *testing.T) {
	ca := newTestCA(t, "private test CA")
	addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
		ackHello(ctrl, "must-not-be-reached")
	})
	dir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		d := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: filepath.Join(dir, "nope.pem")})
		_, err := d.Dial(context.Background())
		require.ErrorIs(t, err, fs.ErrNotExist)
	})
	t.Run("no certificate inside", func(t *testing.T) {
		path := filepath.Join(dir, "garbage.pem")
		require.NoError(t, os.WriteFile(path, []byte("this is not PEM\n"), 0o600))
		d := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: path})
		_, err := d.Dial(context.Background())
		require.ErrorIs(t, err, ErrNoCACertificates)
	})
	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(dir, "empty.pem")
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		d := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: path})
		_, err := d.Dial(context.Background())
		require.ErrorIs(t, err, ErrNoCACertificates)
	})
	// Even with verification switched off a broken ca_file is reported
	// instead of being ignored silently.
	t.Run("missing file with insecure_skip_verify", func(t *testing.T) {
		d := New(Options{ServerAddr: addr, Token: "twbl_x", InsecureSkipVerify: true, CAFile: filepath.Join(dir, "nope.pem")})
		_, err := d.Dial(context.Background())
		require.ErrorIs(t, err, fs.ErrNotExist)
	})
}

// --- timeouts ---------------------------------------------------------------

func TestOptionDefaults(t *testing.T) {
	d := New(Options{})
	assert.Equal(t, 10*time.Second, d.opts.DialTimeout)
	assert.Equal(t, 10*time.Second, d.opts.ReplyTimeout)

	custom := New(Options{DialTimeout: 3 * time.Second, ReplyTimeout: 7 * time.Second})
	assert.Equal(t, 3*time.Second, custom.opts.DialTimeout)
	assert.Equal(t, 7*time.Second, custom.opts.ReplyTimeout)

	disabled := New(Options{DialTimeout: -1, ReplyTimeout: -1})
	assert.Less(t, disabled.opts.DialTimeout, time.Duration(0))
	assert.Less(t, disabled.opts.ReplyTimeout, time.Duration(0))
}

// A server that accepts the TCP connection but never answers the TLS
// handshake must not hold the client forever.
func TestDialTimesOutDuringTLSHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn) // hold it open, never answer
			mu.Unlock()
		}
	}()

	d := New(Options{ServerAddr: ln.Addr().String(), Token: "twbl_x", InsecureSkipVerify: true, DialTimeout: 300 * time.Millisecond})
	var dialErr error
	took := within(t, 10*time.Second, func() {
		_, dialErr = d.Dial(context.Background())
	})
	require.ErrorIs(t, dialErr, ErrDialTimeout)
	assert.GreaterOrEqual(t, took, 300*time.Millisecond)
}

func TestDialTimesOutWaitingForHelloAck(t *testing.T) {
	ca := newTestCA(t, "private test CA")
	wait := untilTestEnds(t)
	addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
		_, _ = readRequest(ctrl) // take the hello, never answer
		wait()
	})

	d := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: ca.writeFile(t), ReplyTimeout: 300 * time.Millisecond})
	var dialErr error
	took := within(t, 10*time.Second, func() {
		_, dialErr = d.Dial(context.Background())
	})
	require.ErrorIs(t, dialErr, ErrReplyTimeout)
	assert.GreaterOrEqual(t, took, 300*time.Millisecond)
}

func TestRegisterTimesOutWaitingForAck(t *testing.T) {
	calls := map[string]func(*Session) error{
		"http": func(s *Session) error { _, err := s.RegisterHTTP(context.Background(), "app"); return err },
		"tcp":  func(s *Session) error { _, err := s.RegisterTCP(context.Background(), 0); return err },
		"udp":  func(s *Session) error { _, err := s.RegisterUDP(context.Background(), 0); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			ca := newTestCA(t, "private test CA")
			wait := untilTestEnds(t)
			addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
				if !ackHello(ctrl, "sess-1") {
					return
				}
				_, _ = readRequest(ctrl) // take the register request, never answer
				wait()
			})

			d := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: ca.writeFile(t), ReplyTimeout: 300 * time.Millisecond})
			sess, err := d.Dial(context.Background())
			require.NoError(t, err)
			defer sess.Close()

			var regErr error
			took := within(t, 10*time.Second, func() { regErr = call(sess) })
			require.ErrorIs(t, regErr, ErrReplyTimeout)
			assert.GreaterOrEqual(t, took, 300*time.Millisecond)

			// A late reply could be taken for the answer to the next request,
			// so the session is unusable after a timeout.
			var acceptErr error
			within(t, 5*time.Second, func() { _, acceptErr = sess.AcceptStream() })
			require.Error(t, acceptErr)
		})
	}
}

// The same slow server is fine when the limit is longer than its delay or
// switched off with a negative value.
func TestReplyTimeoutLongerThanDelayOrDisabled(t *testing.T) {
	for name, timeout := range map[string]time.Duration{"longer": 5 * time.Second, "disabled": -1} {
		t.Run(name, func(t *testing.T) {
			ca := newTestCA(t, "private test CA")
			wait := untilTestEnds(t)
			addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
				if _, err := readRequest(ctrl); err != nil {
					return
				}
				time.Sleep(500 * time.Millisecond)
				if writeReply(ctrl, protocol.TypeHelloAck, protocol.HelloAck{SessionID: "sess-slow"}) != nil {
					return
				}
				if _, err := readRequest(ctrl); err != nil {
					return
				}
				time.Sleep(500 * time.Millisecond)
				_ = writeReply(ctrl, protocol.TypeRegisterHTTPAck, protocol.RegisterHTTPAck{PublicURL: "https://app.example.org", Subdomain: "app"})
				wait()
			})

			d := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: ca.writeFile(t), ReplyTimeout: timeout})
			sess, err := d.Dial(context.Background())
			require.NoError(t, err)
			defer sess.Close()
			assert.Equal(t, "sess-slow", sess.SessionID())

			ack, err := sess.RegisterHTTP(context.Background(), "app")
			require.NoError(t, err)
			assert.Equal(t, "https://app.example.org", ack.PublicURL)
			assert.Equal(t, "app", ack.Subdomain)
		})
	}
}

func TestRegisterReturnsWhenContextIsCancelled(t *testing.T) {
	ca := newTestCA(t, "private test CA")
	wait := untilTestEnds(t)
	addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
		if !ackHello(ctrl, "sess-1") {
			return
		}
		_, _ = readRequest(ctrl)
		wait()
	})

	d := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: ca.writeFile(t), ReplyTimeout: time.Minute})
	sess, err := d.Dial(context.Background())
	require.NoError(t, err)
	defer sess.Close()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	var regErr error
	within(t, 10*time.Second, func() { _, regErr = sess.RegisterTCP(ctx, 0) })
	require.ErrorIs(t, regErr, context.Canceled)
}

// --- reply size -------------------------------------------------------------

// helloAckOfSize builds a valid hello_ack envelope that is exactly size bytes
// long.
func helloAckOfSize(t *testing.T, size int) []byte {
	t.Helper()
	const prefix = `{"type":"hello_ack","payload":{"session_id":"`
	const suffix = `"}}`
	frame := []byte(prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix)
	require.Len(t, frame, size)
	var env protocol.Envelope
	require.NoError(t, json.Unmarshal(frame, &env))
	return frame
}

func TestReplySizeLimit(t *testing.T) {
	dialWithAckOfSize := func(t *testing.T, size int) (*Session, error) {
		ca := newTestCA(t, "private test CA")
		wait := untilTestEnds(t)
		frame := helloAckOfSize(t, size)
		addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
			if _, err := readRequest(ctrl); err != nil {
				return
			}
			if protocol.WriteFrame(ctrl, frame) != nil {
				return
			}
			wait()
		})
		d := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: ca.writeFile(t), ReplyTimeout: 5 * time.Second})
		return d.Dial(context.Background())
	}

	t.Run("65536 bytes are accepted", func(t *testing.T) {
		sess, err := dialWithAckOfSize(t, 65536)
		require.NoError(t, err)
		defer sess.Close()
	})
	t.Run("65537 bytes are rejected", func(t *testing.T) {
		var err error
		within(t, 10*time.Second, func() { _, err = dialWithAckOfSize(t, 65537) })
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrReplyTimeout, "must be refused by size, not by waiting")
		assert.Less(t, len(err.Error()), 300, "the oversized reply must not end up in the error")
	})
}

// --- server text ------------------------------------------------------------

func TestSanitizeServerText(t *testing.T) {
	long256 := strings.Repeat("ä", 256)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "subdomain taken", "subdomain taken"},
		{"empty", "", ""},
		{"printable non-ASCII is kept", "Zürich – ok ✓ 日本", "Zürich – ok ✓ 日本"},
		{"ANSI escape", "bad \x1b[31mtoken\x1b[0m", "bad [31mtoken[0m"},
		{"CR LF and tab", "line1\r\nFAKE: line2\tend", "line1FAKE: line2end"},
		{"NUL BEL DEL", "a\x00b\x07c\x7fd", "abcd"},
		{"C1 controls incl. CSI", "a\u0085b\u009bc", "abc"},
		{"bidi override, zero width, BOM, soft hyphen", "a\u202eb\u200bc\ufeffd\u00ade", "abcde"},
		{"no-break space", "a\u00a0b", "ab"},
		{"invalid UTF-8", "a\xffb\xc0\xafc\xed\xa0\x80d", "abcd"},
		{"truncated multi-byte sequence at the end", "ok\xe2\x82", "ok"},
		{"exactly 256 runes stay as they are", long256, long256},
		{"257 runes are cut to 256 plus marker", long256 + "ä", long256 + "..."},
		{"removed runes do not count towards the limit", strings.Repeat("\x1b", 1000) + "ok", "ok"},
		{"cut happens on a rune boundary", strings.Repeat("a", 255) + "€€", strings.Repeat("a", 255) + "€..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeServerText(tc.in)
			assert.Equal(t, tc.want, got)
			assert.True(t, utf8.ValidString(got))
		})
	}
}

const hostileText = "denied\x1b[2J\x1b[31m\r\nlevel=INFO msg=\"all good\"\x00\u202e" // + padding in the tests

func TestServerErrorTextIsSanitized(t *testing.T) {
	const wantClean = `denied[2J[31mlevel=INFO msg="all good"`
	hostile := hostileText + strings.Repeat("Ω", 400)
	wantText := wantClean + strings.Repeat("Ω", 256-utf8.RuneCountInString(wantClean)) + "..."

	ca := newTestCA(t, "private test CA")
	caFile := ca.writeFile(t)

	t.Run("hello_ack error", func(t *testing.T) {
		addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
			if _, err := readRequest(ctrl); err != nil {
				return
			}
			_ = writeReply(ctrl, protocol.TypeHelloAck, protocol.HelloAck{Error: hostile})
		})
		_, err := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: caFile}).Dial(context.Background())
		require.Error(t, err)
		assert.Equal(t, "auth: "+wantText, err.Error())
		assertPrintable(t, err.Error())
	})

	registerCases := map[string]struct {
		ackType protocol.MessageType
		ack     any
		call    func(*Session) error
	}{
		"register_http_ack error": {protocol.TypeRegisterHTTPAck, protocol.RegisterHTTPAck{Error: hostile},
			func(s *Session) error { _, err := s.RegisterHTTP(context.Background(), ""); return err }},
		"register_tcp_ack error": {protocol.TypeRegisterTCPAck, protocol.RegisterTCPAck{Error: hostile},
			func(s *Session) error { _, err := s.RegisterTCP(context.Background(), 0); return err }},
		"register_udp_ack error": {protocol.TypeRegisterUDPAck, protocol.RegisterUDPAck{Error: hostile},
			func(s *Session) error { _, err := s.RegisterUDP(context.Background(), 0); return err }},
	}
	for name, tc := range registerCases {
		t.Run(name, func(t *testing.T) {
			addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
				if !ackHello(ctrl, "sess-1") {
					return
				}
				if _, err := readRequest(ctrl); err != nil {
					return
				}
				_ = writeReply(ctrl, tc.ackType, tc.ack)
			})
			sess, err := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: caFile}).Dial(context.Background())
			require.NoError(t, err)
			defer sess.Close()

			err = tc.call(sess)
			require.Error(t, err)
			assert.Equal(t, wantText, err.Error())
			assertPrintable(t, err.Error())
		})
	}
}

func TestServerProvidedFieldsAreSanitized(t *testing.T) {
	ca := newTestCA(t, "private test CA")
	caFile := ca.writeFile(t)
	wait := untilTestEnds(t)

	dial := func(t *testing.T, sessionID string, ackType protocol.MessageType, ack any) *Session {
		addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
			if !ackHello(ctrl, sessionID) {
				return
			}
			if _, err := readRequest(ctrl); err != nil {
				return
			}
			if writeReply(ctrl, ackType, ack) != nil {
				return
			}
			wait()
		})
		sess, err := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: caFile}).Dial(context.Background())
		require.NoError(t, err)
		t.Cleanup(func() { _ = sess.Close() })
		return sess
	}

	t.Run("session id", func(t *testing.T) {
		sess := dial(t, "ab\x1b]0;owned\x07cd", protocol.TypeRegisterHTTPAck, protocol.RegisterHTTPAck{})
		assert.Equal(t, "ab]0;ownedcd", sess.SessionID())
	})
	t.Run("http", func(t *testing.T) {
		sess := dial(t, "s", protocol.TypeRegisterHTTPAck, protocol.RegisterHTTPAck{
			PublicURL: "https://app.example.org\x1b[1A\x1b[2K\r✔ tunnel up: https://evil.example",
			Subdomain: "app\r\n\x00",
		})
		ack, err := sess.RegisterHTTP(context.Background(), "app")
		require.NoError(t, err)
		assert.Equal(t, "https://app.example.org[1A[2K✔ tunnel up: https://evil.example", ack.PublicURL)
		assert.Equal(t, "app", ack.Subdomain)
	})
	t.Run("tcp", func(t *testing.T) {
		sess := dial(t, "s", protocol.TypeRegisterTCPAck, protocol.RegisterTCPAck{PublicAddr: "example.org:15042\x1b[2J\n", Port: 15042})
		ack, err := sess.RegisterTCP(context.Background(), 0)
		require.NoError(t, err)
		assert.Equal(t, "example.org:15042[2J", ack.PublicAddr)
		assert.Equal(t, 15042, ack.Port)
	})
	t.Run("udp", func(t *testing.T) {
		sess := dial(t, "s", protocol.TypeRegisterUDPAck, protocol.RegisterUDPAck{PublicAddr: "example.org:35000\x1b[2J\n", Port: 35000})
		ack, err := sess.RegisterUDP(context.Background(), 0)
		require.NoError(t, err)
		assert.Equal(t, "example.org:35000[2J", ack.PublicAddr)
		assert.Equal(t, 35000, ack.Port)
	})
}

func TestUnexpectedReplyTypeIsRejectedAndSanitized(t *testing.T) {
	ca := newTestCA(t, "private test CA")
	caFile := ca.writeFile(t)

	t.Run("instead of hello_ack", func(t *testing.T) {
		addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
			if _, err := readRequest(ctrl); err != nil {
				return
			}
			_ = writeReply(ctrl, protocol.MessageType("pwn\x1b[2J\r\n"), protocol.HelloAck{SessionID: "sess-x"})
		})
		_, err := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: caFile}).Dial(context.Background())
		require.ErrorIs(t, err, ErrUnexpectedReply)
		assertPrintable(t, err.Error())
		assert.Contains(t, err.Error(), "pwn[2J")
	})
	t.Run("ack of another request", func(t *testing.T) {
		addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
			if !ackHello(ctrl, "sess-1") {
				return
			}
			if _, err := readRequest(ctrl); err != nil {
				return
			}
			// A register_tcp_ack must not be taken for a register_http_ack.
			_ = writeReply(ctrl, protocol.TypeRegisterTCPAck, protocol.RegisterTCPAck{PublicAddr: "example.org:1", Port: 1})
		})
		sess, err := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: caFile}).Dial(context.Background())
		require.NoError(t, err)
		defer sess.Close()
		_, err = sess.RegisterHTTP(context.Background(), "")
		require.ErrorIs(t, err, ErrUnexpectedReply)
	})
	t.Run("payload of the wrong JSON type", func(t *testing.T) {
		addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
			if _, err := readRequest(ctrl); err != nil {
				return
			}
			_ = protocol.WriteFrame(ctrl, []byte(`{"type":"hello_ack","payload":5}`))
		})
		_, err := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: caFile}).Dial(context.Background())
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrReplyTimeout)
	})
	t.Run("empty frame", func(t *testing.T) {
		addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
			if _, err := readRequest(ctrl); err != nil {
				return
			}
			_ = protocol.WriteFrame(ctrl, nil)
		})
		_, err := New(Options{ServerAddr: addr, Token: "twbl_x", CAFile: caFile}).Dial(context.Background())
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrReplyTimeout)
	})
}

// The hello carries the configured client version and never the CA path or
// other local details.
func TestHelloCarriesTokenAndClientVersion(t *testing.T) {
	ca := newTestCA(t, "private test CA")
	wait := untilTestEnds(t)
	got := make(chan protocol.Hello, 1)
	addr := startFakeServer(t, loopbackCert(t, ca), func(ctrl protocol.Stream) {
		raw, err := protocol.ReadFrame(ctrl, 1<<20)
		if err != nil {
			return
		}
		var env protocol.Envelope
		var hello protocol.Hello
		if json.Unmarshal(raw, &env) != nil || json.Unmarshal(env.Payload, &hello) != nil {
			return
		}
		got <- hello
		_ = writeReply(ctrl, protocol.TypeHelloAck, protocol.HelloAck{SessionID: "sess-1"})
		wait()
	})

	sess, err := New(Options{ServerAddr: addr, Token: "twbl_secret", ClientVersion: "1.2.3", CAFile: ca.writeFile(t)}).Dial(context.Background())
	require.NoError(t, err)
	defer sess.Close()

	select {
	case hello := <-got:
		assert.Equal(t, "twbl_secret", hello.Token)
		assert.Equal(t, "1.2.3", hello.ClientVersion)
	case <-time.After(5 * time.Second):
		t.Fatal("server never saw the hello")
	}
}
