package mail

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeSMTPConfig describes how the fake server behaves.
type fakeSMTPConfig struct {
	implicitTLS    bool   // TLS from the first byte (port 465 style)
	startTLS       bool   // advertise and accept STARTTLS
	auth           bool   // advertise AUTH PLAIN once the connection is encrypted
	authInClear    bool   // advertise AUTH PLAIN on an unencrypted connection too
	rejectEHLO     bool   // answer 502 to EHLO; only HELO works, so no extensions
	rejectHELO     bool   // answer 502 to HELO as well
	silent         bool   // accept the connection and never say anything
	stallAfterData bool   // take the message and never confirm it
	otherHostCert  bool   // present a certificate for other.example, not for 127.0.0.1
	wantUser       string // credentials AUTH accepts
	wantPass       string
}

// fakeSession is what the server saw on one connection.
type fakeSession struct {
	verbs      []string // command verbs in order
	tlsAtAuth  bool
	tlsAtMail  bool
	authUser   string
	authPass   string
	mailFrom   string
	rcptTo     []string
	data       string
	tlsFailure error
}

func (s *fakeSession) saw(verb string) bool {
	for _, v := range s.verbs {
		if v == verb {
			return true
		}
	}
	return false
}

type fakeSMTP struct {
	t    *testing.T
	cfg  fakeSMTPConfig
	ln   net.Listener
	cert tls.Certificate
	// roots trusts the server certificate; hand it to SMTPConfig.RootCAs.
	roots *x509.CertPool

	mu       sync.Mutex
	sessions []*fakeSession
	conns    []net.Conn
	wg       sync.WaitGroup
}

// startFakeSMTP runs a scripted SMTP server on 127.0.0.1 until the test ends.
func startFakeSMTP(t *testing.T, cfg fakeSMTPConfig) *fakeSMTP {
	t.Helper()
	cert, roots := testCertificate(t, cfg.otherHostCert)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	f := &fakeSMTP{t: t, cfg: cfg, ln: ln, cert: cert, roots: roots}
	f.wg.Add(1)
	go f.acceptLoop()
	t.Cleanup(func() {
		_ = ln.Close()
		f.mu.Lock()
		for _, c := range f.conns {
			_ = c.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
	})
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

// seen returns a copy of the sessions recorded so far.
func (f *fakeSMTP) seen() []fakeSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeSession, 0, len(f.sessions))
	for _, s := range f.sessions {
		out = append(out, *s)
	}
	return out
}

// only returns the single session of a test that connects once.
func (f *fakeSMTP) only() fakeSession {
	f.t.Helper()
	// The client may return before the server goroutine has recorded QUIT.
	deadline := time.Now().Add(2 * time.Second)
	for {
		s := f.seen()
		if len(s) == 1 || time.Now().After(deadline) {
			require.Len(f.t, s, 1, "connections to the fake server")
			return s[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *fakeSMTP) acceptLoop() {
	defer f.wg.Done()
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		sess := &fakeSession{}
		f.mu.Lock()
		f.sessions = append(f.sessions, sess)
		f.conns = append(f.conns, conn)
		f.mu.Unlock()
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer conn.Close()
			f.serve(conn, sess)
		}()
	}
}

func (f *fakeSMTP) record(sess *fakeSession, fn func(*fakeSession)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(sess)
}

func (f *fakeSMTP) serve(conn net.Conn, sess *fakeSession) {
	encrypted := false
	if f.cfg.implicitTLS {
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{f.cert}})
		if err := tc.Handshake(); err != nil {
			f.record(sess, func(s *fakeSession) { s.tlsFailure = err })
			return
		}
		conn = tc
		encrypted = true
	}
	if f.cfg.silent {
		// Hold the connection open without a greeting until the client or
		// the test closes it.
		_, _ = conn.Read(make([]byte, 1))
		return
	}

	tp := textproto.NewConn(conn)
	reply := func(lines ...string) {
		for i, l := range lines {
			sep := "-"
			if i == len(lines)-1 {
				sep = " "
			}
			_ = tp.PrintfLine("%s%s%s", l[:3], sep, l[4:])
		}
	}
	reply("220 fake ESMTP ready")

	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		f.record(sess, func(s *fakeSession) { s.verbs = append(s.verbs, verb) })

		switch verb {
		case "EHLO":
			if f.cfg.rejectEHLO {
				reply("502 command not implemented")
				continue
			}
			lines := []string{"250 fake greets you"}
			if f.cfg.startTLS && !encrypted {
				lines = append(lines, "250 STARTTLS")
			}
			if (f.cfg.auth && encrypted) || f.cfg.authInClear {
				lines = append(lines, "250 AUTH PLAIN")
			}
			lines = append(lines, "250 8BITMIME")
			reply(lines...)
		case "HELO":
			if f.cfg.rejectHELO {
				reply("502 command not implemented")
				continue
			}
			reply("250 fake greets you")
		case "STARTTLS":
			if !f.cfg.startTLS || encrypted {
				reply("502 command not implemented")
				continue
			}
			reply("220 go ahead")
			tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{f.cert}})
			if err := tc.Handshake(); err != nil {
				f.record(sess, func(s *fakeSession) { s.tlsFailure = err })
				return
			}
			conn = tc
			tp = textproto.NewConn(conn)
			encrypted = true
		case "AUTH":
			mech, initial, _ := strings.Cut(arg, " ")
			raw, err := base64.StdEncoding.DecodeString(initial)
			parts := strings.Split(string(raw), "\x00")
			if !strings.EqualFold(mech, "PLAIN") || err != nil || len(parts) != 3 {
				reply("501 malformed AUTH")
				continue
			}
			f.record(sess, func(s *fakeSession) {
				s.tlsAtAuth = encrypted
				s.authUser, s.authPass = parts[1], parts[2]
			})
			if parts[1] == f.cfg.wantUser && parts[2] == f.cfg.wantPass {
				reply("235 authenticated")
			} else {
				reply("535 authentication failed")
			}
		case "MAIL":
			f.record(sess, func(s *fakeSession) {
				s.tlsAtMail = encrypted
				s.mailFrom = strings.TrimPrefix(arg, "FROM:")
			})
			reply("250 sender ok")
		case "RCPT":
			f.record(sess, func(s *fakeSession) { s.rcptTo = append(s.rcptTo, strings.TrimPrefix(arg, "TO:")) })
			reply("250 recipient ok")
		case "DATA":
			reply("354 end with <CRLF>.<CRLF>")
			body, err := io.ReadAll(tp.DotReader())
			if err != nil {
				return
			}
			f.record(sess, func(s *fakeSession) { s.data = string(body) })
			if f.cfg.stallAfterData {
				_, _ = conn.Read(make([]byte, 1))
				return
			}
			reply("250 queued")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("500 unknown command")
		}
	}
}

// testCertificate makes a self-signed certificate and a pool that trusts
// it. The certificate is for the address 127.0.0.1 and for no name, so that
// it verifies only for the host the tests configure. With otherHost it is
// for other.example instead.
func testCertificate(t *testing.T, otherHost bool) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake smtp"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	if otherHost {
		tmpl.IPAddresses = nil
		tmpl.DNSNames = []string{"other.example"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
