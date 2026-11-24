package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Defaults for the timeouts in SMTPConfig.
const (
	DefaultSMTPDialTimeout = 10 * time.Second
	DefaultSMTPSendTimeout = 30 * time.Second
)

// implicitTLSPort is the port on which SMTP servers expect TLS from the
// first byte instead of STARTTLS.
const implicitTLSPort = 465

var (
	// ErrInvalidHeader is returned by SMTPMailer.Send when the sender, the
	// recipient or the subject contains a carriage return or a line feed.
	// Such a value would add header lines of the caller's choosing.
	ErrInvalidHeader = errors.New("mail: header value contains a line break")

	// ErrTLSRequired is returned by SMTPMailer.Send when the server does not
	// offer STARTTLS and SMTPConfig.AllowPlaintext is not set. Nothing has
	// been sent at that point: no credentials, no envelope, no message.
	ErrTLSRequired = errors.New("mail: server offers no STARTTLS and plaintext delivery is not allowed")

	// ErrAuthUnavailable is returned by SMTPMailer.Send when
	// SMTPConfig.AuthRequired is set and the server does not offer AUTH.
	ErrAuthUnavailable = errors.New("mail: server offers no AUTH but authentication is required")
)

// SMTPConfig configures an SMTP mailer.
//
// By default the connection must be encrypted: STARTTLS, or TLS from the
// first byte when Port is 465. The server certificate is always verified
// against Host. For production point at a transactional service (Resend,
// Postmark, etc.) with AuthRequired and credentials. For a local catcher
// without TLS such as Mailhog set AllowPlaintext and leave AuthRequired
// false.
type SMTPConfig struct {
	Host         string
	Port         int
	Username     string
	Password     string
	From         string
	AuthRequired bool

	// AllowPlaintext permits delivery over an unencrypted connection when
	// the server does not offer STARTTLS. The zero value, false, is the safe
	// setting: Send fails with ErrTLSRequired instead. Set it only for a
	// mail catcher on the same machine (the local Mailhog setup). It weakens
	// nothing else: a server that does offer STARTTLS is still upgraded and
	// its certificate still verified, and port 465 always uses TLS.
	AllowPlaintext bool

	// DialTimeout bounds the TCP connect. Zero selects
	// DefaultSMTPDialTimeout (10 s); a negative value leaves the connect to
	// SendTimeout and the context.
	DialTimeout time.Duration

	// SendTimeout bounds one Send from connect to QUIT; a context deadline
	// that ends earlier wins. Zero selects DefaultSMTPSendTimeout (30 s);
	// with a negative value only the context bounds the send.
	SendTimeout time.Duration

	// RootCAs is the set of certificate authorities the server certificate
	// must chain to. nil selects the system roots. It can only replace the
	// trust anchors; there is no way to switch verification off.
	RootCAs *x509.CertPool
}

// SMTPMailer sends email via any SMTP host.
type SMTPMailer struct {
	cfg         SMTPConfig
	dialTimeout time.Duration // 0: none
	sendTimeout time.Duration // 0: none
	implicitTLS bool          // TLS from the first byte; true for port 465
}

// NewSMTPMailer builds an SMTPMailer.
func NewSMTPMailer(cfg SMTPConfig) *SMTPMailer {
	m := &SMTPMailer{
		cfg:         cfg,
		dialTimeout: cfg.DialTimeout,
		sendTimeout: cfg.SendTimeout,
		implicitTLS: cfg.Port == implicitTLSPort,
	}
	switch {
	case m.dialTimeout == 0:
		m.dialTimeout = DefaultSMTPDialTimeout
	case m.dialTimeout < 0:
		m.dialTimeout = 0
	}
	switch {
	case m.sendTimeout == 0:
		m.sendTimeout = DefaultSMTPSendTimeout
	case m.sendTimeout < 0:
		m.sendTimeout = 0
	}
	return m
}

// Send delivers msg via SMTP.
//
// The steps, each of which fails the send instead of being skipped:
// connect within DialTimeout; TLS (immediately on port 465, otherwise
// STARTTLS, which is required unless AllowPlaintext is set); AUTH when
// AuthRequired is set; envelope and message. The whole exchange ends at the
// earlier of the context's deadline and SendTimeout, and cancelling the
// context aborts it.
//
// Send returns ErrInvalidHeader, before it connects, when the sender, the
// recipient or the subject contains CR or LF.
func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	if err := checkHeaderValues(m.cfg.From, msg.To, msg.Subject); err != nil {
		return err
	}
	if m.sendTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.sendTimeout)
		defer cancel()
	}

	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	dialer := net.Dialer{Timeout: m.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("mail: connect to %s aborted: %w", addr, ctxErr)
		}
		return fmt.Errorf("mail: connect to %s: %w", addr, err)
	}
	defer conn.Close()

	// When the context ends, by deadline or by cancellation, the connection
	// deadline moves into the past. That fails every read and write from then
	// on and unblocks the one in progress.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if err := m.deliver(ctx, conn, msg); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("mail: send via %s aborted: %w", addr, ctxErr)
		}
		return err
	}
	return nil
}

// deliver runs the SMTP conversation on an established connection.
func (m *SMTPMailer) deliver(ctx context.Context, conn net.Conn, msg Message) error {
	tlsConfig := &tls.Config{
		ServerName: m.cfg.Host,
		RootCAs:    m.cfg.RootCAs,
		MinVersion: tls.VersionTLS12,
	}

	if m.implicitTLS {
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("mail: TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return fmt.Errorf("mail: greeting: %w", err)
	}
	defer c.Close()

	// Hello sends EHLO and falls back to HELO when the server refuses it.
	// After a fallback the server has announced no extensions, so the checks
	// below fail the send instead of quietly going on without TLS and AUTH.
	if err := c.Hello("localhost"); err != nil {
		return fmt.Errorf("mail: hello: %w", err)
	}

	if !m.implicitTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("mail: STARTTLS: %w", err)
			}
		} else if !m.cfg.AllowPlaintext {
			return ErrTLSRequired
		}
	}

	if m.cfg.AuthRequired {
		if ok, _ := c.Extension("AUTH"); !ok {
			return ErrAuthUnavailable
		}
		// PlainAuth itself refuses to send the password over an unencrypted
		// connection to anything but localhost.
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("mail: auth: %w", err)
		}
	}

	if err := c.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("mail: sender: %w", err)
	}
	if err := c.Rcpt(msg.To); err != nil {
		return fmt.Errorf("mail: recipient: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mail: data: %w", err)
	}
	if _, err := w.Write(m.compose(msg)); err != nil {
		return fmt.Errorf("mail: write message: %w", err)
	}
	// Close sends the final dot and waits for the server to accept the
	// message. Only then is it delivered.
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: message not accepted: %w", err)
	}
	// The message is accepted; a failing QUIT changes nothing about that.
	_ = c.Quit()
	return nil
}

// compose builds headers and body. The header values have passed
// checkHeaderValues.
func (m *SMTPMailer) compose(msg Message) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", m.cfg.From)
	fmt.Fprintf(&buf, "To: %s\r\n", msg.To)
	fmt.Fprintf(&buf, "Subject: %s\r\n", msg.Subject)
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	if msg.HTMLBody != "" {
		const boundary = "tunnel-boundary-42"
		fmt.Fprintf(&buf, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
		fmt.Fprintf(&buf, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n", boundary, msg.TextBody)
		fmt.Fprintf(&buf, "--%s\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s\r\n", boundary, msg.HTMLBody)
		fmt.Fprintf(&buf, "--%s--\r\n", boundary)
	} else {
		fmt.Fprintf(&buf, "Content-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n", msg.TextBody)
	}
	return buf.Bytes()
}

// checkHeaderValues returns ErrInvalidHeader when a value that goes into a
// header line contains CR or LF.
func checkHeaderValues(from, to, subject string) error {
	for _, v := range []struct{ name, value string }{
		{"From", from}, {"To", to}, {"Subject", subject},
	} {
		if strings.ContainsAny(v.value, "\r\n") {
			return fmt.Errorf("%w: %s", ErrInvalidHeader, v.name)
		}
	}
	return nil
}
