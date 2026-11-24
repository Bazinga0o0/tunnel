// Package dialer connects a tunnel client to the server and performs the
// control-plane handshake.
package dialer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

const (
	// DefaultDialTimeout bounds the TCP connect plus the TLS handshake.
	DefaultDialTimeout = 10 * time.Second
	// DefaultReplyTimeout bounds the wait for one control reply.
	DefaultReplyTimeout = 10 * time.Second
	// MaxReplySize is the largest control frame accepted from the server.
	// Replies are small JSON objects; anything larger is refused before it is
	// read into memory.
	MaxReplySize = 64 << 10

	// maxServerTextRunes is how much of a server-provided text (an error
	// message, a public URL) is kept for display.
	maxServerTextRunes = 256
)

var (
	// ErrNoCACertificates: Options.CAFile does not contain a PEM certificate.
	ErrNoCACertificates = errors.New("no CA certificate found")
	// ErrDialTimeout: connecting or the TLS handshake took longer than
	// Options.DialTimeout.
	ErrDialTimeout = errors.New("timed out connecting to the server")
	// ErrReplyTimeout: the server did not answer a control request within
	// Options.ReplyTimeout.
	ErrReplyTimeout = errors.New("timed out waiting for the server's reply")
	// ErrUnexpectedReply: the server answered with a message of another type
	// than the request calls for.
	ErrUnexpectedReply = errors.New("unexpected reply from the server")
)

// Options configures a Dialer.
//
// Convention for the durations: zero selects the default, a negative value
// switches the limit off.
type Options struct {
	ServerAddr         string
	Token              string
	ClientVersion      string
	InsecureSkipVerify bool

	// CAFile is the path of a PEM file with the CA certificate(s) the server
	// certificate must chain to (private CA). When set, only these CAs are
	// trusted; the system trust store is not used. The host name is still
	// checked. A file that cannot be read or holds no certificate makes Dial
	// fail; there is no fallback to the system store.
	CAFile string

	// DialTimeout bounds the TCP connect plus the TLS handshake.
	// Zero: DefaultDialTimeout. Negative: no limit besides the context.
	DialTimeout time.Duration

	// ReplyTimeout bounds each control exchange (hello and the register
	// requests): sending the request and waiting for its reply.
	// Zero: DefaultReplyTimeout. Negative: no limit besides the context.
	ReplyTimeout time.Duration
}

type Dialer struct {
	opts Options
}

func New(opts Options) *Dialer {
	if opts.ClientVersion == "" {
		opts.ClientVersion = "0.1.0"
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = DefaultDialTimeout
	}
	if opts.ReplyTimeout == 0 {
		opts.ReplyTimeout = DefaultReplyTimeout
	}
	return &Dialer{opts: opts}
}

type Session struct {
	mux          protocol.Session
	ctrl         protocol.Stream
	ctrlMu       sync.Mutex
	sessionID    string
	replyTimeout time.Duration
}

// tlsConfig builds the client TLS configuration from the options.
func (d *Dialer) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{InsecureSkipVerify: d.opts.InsecureSkipVerify, MinVersion: tls.VersionTLS12}
	if d.opts.CAFile == "" {
		return cfg, nil
	}
	pemBytes, err := os.ReadFile(d.opts.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("ca_file %s: %w", d.opts.CAFile, ErrNoCACertificates)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

func (d *Dialer) Dial(ctx context.Context) (*Session, error) {
	tlsCfg, err := d.tlsConfig()
	if err != nil {
		return nil, err
	}

	dialCtx := ctx
	if d.opts.DialTimeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, d.opts.DialTimeout)
		defer cancel()
	}
	dialer := &tls.Dialer{Config: tlsCfg}
	conn, err := dialer.DialContext(dialCtx, "tcp", d.opts.ServerAddr)
	if err != nil {
		if ctx.Err() == nil && errors.Is(dialCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("dial %s: %w (limit %s)", d.opts.ServerAddr, ErrDialTimeout, d.opts.DialTimeout)
		}
		return nil, fmt.Errorf("dial: %w", err)
	}

	mux, err := protocol.NewClientSession(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("yamux client: %w", err)
	}

	ctrl, err := mux.OpenStream()
	if err != nil {
		_ = mux.Close()
		return nil, fmt.Errorf("open ctrl stream: %w", err)
	}

	sess := &Session{mux: mux, ctrl: ctrl, replyTimeout: d.opts.ReplyTimeout}

	hello := protocol.Hello{
		Token:         d.opts.Token,
		ClientVersion: d.opts.ClientVersion,
		OS:            runtime.GOOS,
	}
	var ack protocol.HelloAck
	if err := sess.exchange(ctx, protocol.TypeHello, &hello, protocol.TypeHelloAck, &ack); err != nil {
		return nil, fmt.Errorf("hello: %w", err)
	}
	if ack.Error != "" {
		_ = mux.Close()
		return nil, fmt.Errorf("auth: %s", sanitizeServerText(ack.Error))
	}
	sess.sessionID = sanitizeServerText(ack.SessionID)
	return sess, nil
}

func (s *Session) SessionID() string { return s.sessionID }

// RegisterHTTP asks the server for an HTTP tunnel. The texts in the returned
// ack are cleaned for display (see sanitizeServerText).
func (s *Session) RegisterHTTP(ctx context.Context, subdomain string) (*protocol.RegisterHTTPAck, error) {
	req := protocol.RegisterHTTP{Subdomain: subdomain}
	var ack protocol.RegisterHTTPAck
	if err := s.exchange(ctx, protocol.TypeRegisterHTTP, &req, protocol.TypeRegisterHTTPAck, &ack); err != nil {
		return nil, err
	}
	if ack.Error != "" {
		return nil, errors.New(sanitizeServerText(ack.Error))
	}
	ack.PublicURL = sanitizeServerText(ack.PublicURL)
	ack.Subdomain = sanitizeServerText(ack.Subdomain)
	return &ack, nil
}

// RegisterTCP asks the server to allocate a public TCP port and bind a
// listener to it. preferredPort = 0 lets the server pick.
func (s *Session) RegisterTCP(ctx context.Context, preferredPort int) (*protocol.RegisterTCPAck, error) {
	req := protocol.RegisterTCP{Port: preferredPort}
	var ack protocol.RegisterTCPAck
	if err := s.exchange(ctx, protocol.TypeRegisterTCP, &req, protocol.TypeRegisterTCPAck, &ack); err != nil {
		return nil, err
	}
	if ack.Error != "" {
		return nil, errors.New(sanitizeServerText(ack.Error))
	}
	ack.PublicAddr = sanitizeServerText(ack.PublicAddr)
	return &ack, nil
}

// RegisterUDP asks the server to allocate a public UDP port and bind a
// listener to it. preferredPort = 0 lets the server pick.
func (s *Session) RegisterUDP(ctx context.Context, preferredPort int) (*protocol.RegisterUDPAck, error) {
	req := protocol.RegisterUDP{Port: preferredPort}
	var ack protocol.RegisterUDPAck
	if err := s.exchange(ctx, protocol.TypeRegisterUDP, &req, protocol.TypeRegisterUDPAck, &ack); err != nil {
		return nil, err
	}
	if ack.Error != "" {
		return nil, errors.New(sanitizeServerText(ack.Error))
	}
	ack.PublicAddr = sanitizeServerText(ack.PublicAddr)
	return &ack, nil
}

func (s *Session) AcceptStream() (protocol.Stream, error) {
	return s.mux.AcceptStream()
}

func (s *Session) Close() error {
	return s.mux.Close()
}

// deadliner is implemented by yamux streams (and net.Conn in tests).
type deadliner interface {
	SetDeadline(time.Time) error
}

// exchange sends one control request and reads its reply into ack. It is
// bounded by the session's reply timeout and by ctx.
//
// When the exchange itself fails (timeout, cancelled context, a reply of the
// wrong type or one that cannot be decoded) the session is closed: a reply
// that arrives late could otherwise be taken for the answer to the next
// request. An error reported inside a well-formed ack is not such a failure.
func (s *Session) exchange(ctx context.Context, reqType protocol.MessageType, req any, wantType protocol.MessageType, ack any) error {
	s.ctrlMu.Lock()
	defer s.ctrlMu.Unlock()

	err := s.exchangeLocked(ctx, reqType, req, wantType, ack)
	if err != nil {
		_ = s.mux.Close()
	}
	return err
}

func (s *Session) exchangeLocked(ctx context.Context, reqType protocol.MessageType, req any, wantType protocol.MessageType, ack any) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if dl, ok := s.ctrl.(deadliner); ok {
		deadline := time.Time{}
		if s.replyTimeout > 0 {
			deadline = time.Now().Add(s.replyTimeout)
		}
		_ = dl.SetDeadline(deadline)

		// A cancelled context interrupts the exchange at once by moving the
		// deadline into the past.
		interrupted := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			defer close(interrupted)
			_ = dl.SetDeadline(time.Unix(1, 0))
		})
		defer func() {
			if !stop() {
				<-interrupted
			}
			_ = dl.SetDeadline(time.Time{})
		}()
	}

	if err := writeEnvelope(s.ctrl, reqType, req); err != nil {
		return s.exchangeError(ctx, err)
	}
	env, err := readEnvelope(s.ctrl)
	if err != nil {
		return s.exchangeError(ctx, err)
	}
	if env.Type != wantType {
		return fmt.Errorf("%w: got type %q, want %q", ErrUnexpectedReply, sanitizeServerText(string(env.Type)), wantType)
	}
	if err := json.Unmarshal(env.Payload, ack); err != nil {
		return fmt.Errorf("decode %s: %w", wantType, err)
	}
	return nil
}

// exchangeError maps a transport error of an exchange to its cause.
func (s *Session) exchangeError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("%w (limit %s)", ErrReplyTimeout, s.replyTimeout)
	}
	return err
}

// sanitizeServerText is SanitizeText with the cut used for texts the server
// sends in its replies.
func sanitizeServerText(s string) string {
	return SanitizeText(s, maxServerTextRunes)
}

// SanitizeText makes a text that may contain bytes chosen by the peer safe
// to print on a terminal: bytes that are not valid UTF-8 and runes that are
// not printable (control characters, escape, line breaks, bidirectional
// overrides, zero-width characters) are dropped, and the result is cut after
// maxRunes runes, marked by "...". The ASCII space is kept. A maxRunes below
// 1 switches the cut off.
//
// The dialer applies it to everything it returns from a server reply.
// Callers need it for other peer-influenced text, for example the error of
// a failed TLS verification, which quotes names from the peer's certificate.
func SanitizeText(s string, maxRunes int) string {
	var b strings.Builder
	kept := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == utf8.RuneError && size <= 1 {
			continue
		}
		if !unicode.IsPrint(r) {
			continue
		}
		if maxRunes > 0 && kept == maxRunes {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
		kept++
	}
	return b.String()
}

func writeEnvelope(w protocol.Stream, t protocol.MessageType, payload interface{}) error {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		raw = b
	}
	b, err := json.Marshal(protocol.Envelope{Type: t, Payload: raw})
	if err != nil {
		return err
	}
	return protocol.WriteFrame(w, b)
}

func readEnvelope(r protocol.Stream) (*protocol.Envelope, error) {
	raw, err := protocol.ReadFrame(r, MaxReplySize)
	if err != nil {
		return nil, err
	}
	var env protocol.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	return &env, nil
}
