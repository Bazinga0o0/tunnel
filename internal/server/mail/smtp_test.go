package mail

import (
	"context"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testMessage = Message{
	To:       "rcpt@example.com",
	Subject:  "hello",
	TextBody: "line one\nline two\n",
}

// sendWithin runs Send and fails the test when it does not come back in
// time, so that a mailer that ignores deadlines fails instead of hanging.
func sendWithin(t *testing.T, limit time.Duration, m *SMTPMailer, ctx context.Context, msg Message) (error, time.Duration) {
	t.Helper()
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- m.Send(ctx, msg) }()
	select {
	case err := <-done:
		return err, time.Since(start)
	case <-time.After(limit):
		t.Fatalf("Send did not return within %v", limit)
		return nil, 0
	}
}

// send is sendWithin with a generous limit and no context deadline.
func send(t *testing.T, m *SMTPMailer, msg Message) error {
	t.Helper()
	err, _ := sendWithin(t, 10*time.Second, m, context.Background(), msg)
	return err
}

// mailerFor builds a mailer for the fake server; adjust changes the config.
func mailerFor(srv *fakeSMTP, adjust func(*SMTPConfig)) *SMTPMailer {
	cfg := SMTPConfig{
		Host:    "127.0.0.1",
		Port:    srv.port(),
		From:    "noreply@example.com",
		RootCAs: srv.roots,
	}
	if adjust != nil {
		adjust(&cfg)
	}
	return NewSMTPMailer(cfg)
}

// assertNothingSent checks that the server saw neither credentials nor an
// envelope nor a message.
func assertNothingSent(t *testing.T, sess fakeSession) {
	t.Helper()
	assert.False(t, sess.saw("AUTH"), "no credentials (saw %v)", sess.verbs)
	assert.False(t, sess.saw("MAIL"), "no envelope (saw %v)", sess.verbs)
	assert.False(t, sess.saw("RCPT"))
	assert.False(t, sess.saw("DATA"))
	assert.Empty(t, sess.authPass)
	assert.Empty(t, sess.data)
}

// --- TLS required -------------------------------------------------------------

func TestSMTPRefusesPlaintextByDefault(t *testing.T) {
	t.Run("server without STARTTLS", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{})
		// Exactly the configuration existing callers build: no new field set.
		m := NewSMTPMailer(SMTPConfig{Host: "127.0.0.1", Port: srv.port(), From: "noreply@example.com"})

		err := send(t, m, testMessage)
		require.ErrorIs(t, err, ErrTLSRequired)
		assertNothingSent(t, srv.only())
	})

	t.Run("credentials are not offered to a server without STARTTLS", func(t *testing.T) {
		// The server would take AUTH in the clear. The mailer must stop
		// before it gets that far.
		srv := startFakeSMTP(t, fakeSMTPConfig{authInClear: true, wantUser: "user", wantPass: "secret"})
		m := mailerFor(srv, func(c *SMTPConfig) {
			c.AuthRequired, c.Username, c.Password = true, "user", "secret"
		})

		err := send(t, m, testMessage)
		require.ErrorIs(t, err, ErrTLSRequired)
		assertNothingSent(t, srv.only())
	})

	t.Run("a refused EHLO is not a way around TLS", func(t *testing.T) {
		// The server answers EHLO with an error, so the client falls back
		// to HELO and learns of no extension. net/smtp.SendMail then sent
		// the mail without TLS and without AUTH.
		srv := startFakeSMTP(t, fakeSMTPConfig{rejectEHLO: true, startTLS: true, auth: true})
		m := mailerFor(srv, func(c *SMTPConfig) {
			c.AuthRequired, c.Username, c.Password = true, "user", "secret"
		})

		err := send(t, m, testMessage)
		require.ErrorIs(t, err, ErrTLSRequired)
		sess := srv.only()
		assert.Equal(t, []string{"EHLO", "HELO"}, sess.verbs[:2])
		assertNothingSent(t, sess)
	})

	t.Run("a server that refuses the greeting altogether is reported as such", func(t *testing.T) {
		// Neither EHLO nor HELO is accepted. That is a broken server, not a
		// missing STARTTLS, and nothing may follow.
		srv := startFakeSMTP(t, fakeSMTPConfig{rejectEHLO: true, rejectHELO: true})
		m := mailerFor(srv, nil)

		err := send(t, m, testMessage)
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrTLSRequired, "the error names the refused greeting")
		sess := srv.only()
		assert.Equal(t, []string{"EHLO", "HELO"}, sess.verbs, "the send stops after the refused greeting")
	})
}

func TestSMTPDeliversOverStartTLS(t *testing.T) {
	srv := startFakeSMTP(t, fakeSMTPConfig{startTLS: true, auth: true, wantUser: "user", wantPass: "secret"})
	m := mailerFor(srv, func(c *SMTPConfig) {
		c.AuthRequired, c.Username, c.Password = true, "user", "secret"
	})

	require.NoError(t, send(t, m, Message{
		To:       "rcpt@example.com",
		Subject:  "Verify your email",
		TextBody: "first line\n.\n..leading dots\nlast line",
		HTMLBody: "<p>first line</p>",
	}))

	sess := srv.only()
	assert.Equal(t, []string{"EHLO", "STARTTLS", "EHLO", "AUTH", "MAIL", "RCPT", "DATA", "QUIT"}, sess.verbs)
	assert.True(t, sess.tlsAtAuth, "credentials only after the upgrade")
	assert.True(t, sess.tlsAtMail, "envelope only after the upgrade")
	assert.Equal(t, "user", sess.authUser)
	assert.Equal(t, "secret", sess.authPass)
	assert.Equal(t, "<noreply@example.com>", strings.Fields(sess.mailFrom)[0])
	assert.Equal(t, []string{"<rcpt@example.com>"}, sess.rcptTo)

	head, body, found := strings.Cut(sess.data, "\n\n")
	require.True(t, found, "blank line between headers and body")
	assert.Equal(t, []string{
		"From: noreply@example.com",
		"To: rcpt@example.com",
		"Subject: Verify your email",
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="tunnel-boundary-42"`,
	}, strings.Split(head, "\n"))
	assert.Contains(t, body, "first line\n.\n..leading dots\nlast line\n", "dots at line start survive the transfer")
	assert.Contains(t, body, "<p>first line</p>")
}

func TestSMTPVerifiesTheServerCertificate(t *testing.T) {
	t.Run("unknown issuer", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{startTLS: true, auth: true, wantUser: "user", wantPass: "secret"})
		m := mailerFor(srv, func(c *SMTPConfig) {
			c.RootCAs = nil // system roots: they do not know the test certificate
			c.AuthRequired, c.Username, c.Password = true, "user", "secret"
		})

		err := send(t, m, testMessage)
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrTLSRequired)
		assertNothingSent(t, srv.only())
	})

	t.Run("certificate for another host", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{startTLS: true, auth: true, otherHostCert: true, wantUser: "user", wantPass: "secret"})
		m := mailerFor(srv, func(c *SMTPConfig) {
			c.AuthRequired, c.Username, c.Password = true, "user", "secret"
		})

		err := send(t, m, testMessage)
		require.Error(t, err)
		assertNothingSent(t, srv.only())
	})

	t.Run("AllowPlaintext does not switch verification off", func(t *testing.T) {
		// The server offers STARTTLS with a certificate nobody trusts. The
		// mailer must fail, not fall back to the clear.
		srv := startFakeSMTP(t, fakeSMTPConfig{startTLS: true})
		m := mailerFor(srv, func(c *SMTPConfig) {
			c.RootCAs = nil
			c.AllowPlaintext = true
		})

		err := send(t, m, testMessage)
		require.Error(t, err)
		assertNothingSent(t, srv.only())
	})
}

// --- AUTH required ------------------------------------------------------------

func TestSMTPRequiresAuthWhenConfigured(t *testing.T) {
	t.Run("server offers no AUTH", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{startTLS: true})
		m := mailerFor(srv, func(c *SMTPConfig) {
			c.AuthRequired, c.Username, c.Password = true, "user", "secret"
		})

		err := send(t, m, testMessage)
		require.ErrorIs(t, err, ErrAuthUnavailable)
		sess := srv.only()
		assert.True(t, sess.saw("STARTTLS"))
		assertNothingSent(t, sess)
	})

	t.Run("server refuses the credentials", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{startTLS: true, auth: true, wantUser: "user", wantPass: "secret"})
		m := mailerFor(srv, func(c *SMTPConfig) {
			c.AuthRequired, c.Username, c.Password = true, "user", "wrong"
		})

		err := send(t, m, testMessage)
		require.Error(t, err)
		// The caller gets the server's refusal of the credentials, not
		// whatever goes wrong afterwards.
		var reply *textproto.Error
		require.ErrorAs(t, err, &reply)
		assert.Equal(t, 535, reply.Code)
		sess := srv.only()
		assert.True(t, sess.saw("AUTH"))
		assert.False(t, sess.saw("MAIL"), "no envelope after a failed AUTH")
		assert.Empty(t, sess.data)
	})

	t.Run("a refused EHLO is not a way around AUTH", func(t *testing.T) {
		// Plaintext is allowed here, so TLS is not what stops the send. The
		// missing AUTH must.
		srv := startFakeSMTP(t, fakeSMTPConfig{rejectEHLO: true, authInClear: true})
		m := mailerFor(srv, func(c *SMTPConfig) {
			c.AllowPlaintext = true
			c.AuthRequired, c.Username, c.Password = true, "user", "secret"
		})

		err := send(t, m, testMessage)
		require.ErrorIs(t, err, ErrAuthUnavailable)
		assertNothingSent(t, srv.only())
	})

	t.Run("without AuthRequired no credentials are sent", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{startTLS: true, auth: true, wantUser: "user", wantPass: "secret"})
		m := mailerFor(srv, func(c *SMTPConfig) { c.Username, c.Password = "user", "secret" })

		require.NoError(t, send(t, m, testMessage))
		sess := srv.only()
		assert.False(t, sess.saw("AUTH"))
		assert.True(t, sess.tlsAtMail)
	})
}

// --- plaintext only on request --------------------------------------------------

func TestSMTPAllowPlaintext(t *testing.T) {
	t.Run("delivers to a server without STARTTLS (local Mailhog)", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{})
		m := NewSMTPMailer(SMTPConfig{
			Host: "127.0.0.1", Port: srv.port(), From: "noreply@tunnel.localhost",
			AllowPlaintext: true,
		})

		require.NoError(t, send(t, m, testMessage))
		sess := srv.only()
		assert.Equal(t, []string{"EHLO", "MAIL", "RCPT", "DATA", "QUIT"}, sess.verbs)
		assert.False(t, sess.tlsAtMail)
		assert.Contains(t, sess.data, "Subject: hello\n")
		assert.Contains(t, sess.data, "\n\nline one\nline two\n")
	})

	t.Run("still upgrades when the server offers STARTTLS", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{startTLS: true})
		m := mailerFor(srv, func(c *SMTPConfig) { c.AllowPlaintext = true })

		require.NoError(t, send(t, m, testMessage))
		sess := srv.only()
		assert.True(t, sess.saw("STARTTLS"))
		assert.True(t, sess.tlsAtMail)
	})
}

// --- implicit TLS ---------------------------------------------------------------

func TestSMTPImplicitTLS(t *testing.T) {
	t.Run("port 465 selects TLS from the first byte", func(t *testing.T) {
		assert.True(t, NewSMTPMailer(SMTPConfig{Host: "mail.example.com", Port: 465}).implicitTLS)
		assert.True(t, NewSMTPMailer(SMTPConfig{Host: "mail.example.com", Port: 465, AllowPlaintext: true}).implicitTLS,
			"AllowPlaintext does not undo it")
		for _, port := range []int{25, 587, 1025, 2525, 0} {
			assert.False(t, NewSMTPMailer(SMTPConfig{Host: "mail.example.com", Port: port}).implicitTLS, "port %d", port)
		}
	})

	t.Run("delivers", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{implicitTLS: true, auth: true, wantUser: "user", wantPass: "secret"})
		m := mailerFor(srv, func(c *SMTPConfig) {
			c.AuthRequired, c.Username, c.Password = true, "user", "secret"
		})
		m.implicitTLS = true // what port 465 sets; the fake server cannot bind 465

		require.NoError(t, send(t, m, testMessage))
		sess := srv.only()
		assert.Equal(t, []string{"EHLO", "AUTH", "MAIL", "RCPT", "DATA", "QUIT"}, sess.verbs)
		assert.True(t, sess.tlsAtAuth)
		assert.True(t, sess.tlsAtMail)
	})

	t.Run("verifies the certificate", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{implicitTLS: true})
		m := mailerFor(srv, func(c *SMTPConfig) { c.RootCAs = nil })
		m.implicitTLS = true

		require.Error(t, send(t, m, testMessage))
		sess := srv.only()
		assert.Empty(t, sess.verbs, "no SMTP command after a failed handshake")
	})

	t.Run("a server that speaks plain SMTP on the TLS port is refused", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{})
		m := mailerFor(srv, func(c *SMTPConfig) { c.AllowPlaintext = true })
		m.implicitTLS = true

		require.Error(t, send(t, m, testMessage))
		assertNothingSent(t, srv.only())
	})
}

// --- timeouts -------------------------------------------------------------------

func TestSMTPTimeouts(t *testing.T) {
	t.Run("zero selects the defaults, negative switches off", func(t *testing.T) {
		assert.Equal(t, 10*time.Second, DefaultSMTPDialTimeout)
		assert.Equal(t, 30*time.Second, DefaultSMTPSendTimeout)

		m := NewSMTPMailer(SMTPConfig{})
		assert.Equal(t, 10*time.Second, m.dialTimeout)
		assert.Equal(t, 30*time.Second, m.sendTimeout)

		m = NewSMTPMailer(SMTPConfig{DialTimeout: 3 * time.Second, SendTimeout: 7 * time.Second})
		assert.Equal(t, 3*time.Second, m.dialTimeout)
		assert.Equal(t, 7*time.Second, m.sendTimeout)

		m = NewSMTPMailer(SMTPConfig{DialTimeout: -1, SendTimeout: -1})
		assert.Zero(t, m.dialTimeout)
		assert.Zero(t, m.sendTimeout)
	})

	t.Run("SendTimeout ends a send to a silent server", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{silent: true})
		m := mailerFor(srv, func(c *SMTPConfig) { c.SendTimeout = 300 * time.Millisecond })

		err, took := sendWithin(t, 10*time.Second, m, context.Background(), testMessage)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.GreaterOrEqual(t, took, 250*time.Millisecond)
		assert.Less(t, took, 5*time.Second)
	})

	t.Run("an earlier context deadline wins", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{silent: true})
		m := mailerFor(srv, nil) // default SendTimeout: 30 s

		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		err, took := sendWithin(t, 10*time.Second, m, ctx, testMessage)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Less(t, took, 5*time.Second)
	})

	t.Run("cancelling the context aborts the send", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{silent: true})
		m := mailerFor(srv, func(c *SMTPConfig) { c.SendTimeout = -1 })

		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(200*time.Millisecond, cancel)
		err, took := sendWithin(t, 10*time.Second, m, ctx, testMessage)
		require.ErrorIs(t, err, context.Canceled)
		assert.Less(t, took, 5*time.Second)
	})

	t.Run("a message the server never confirms is an error", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{startTLS: true, stallAfterData: true})
		m := mailerFor(srv, func(c *SMTPConfig) { c.SendTimeout = 400 * time.Millisecond })

		err, took := sendWithin(t, 10*time.Second, m, context.Background(), testMessage)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Less(t, took, 5*time.Second)
	})

	t.Run("DialTimeout ends a connect that gets no answer", func(t *testing.T) {
		// 192.0.2.1 is reserved for documentation (RFC 5737): packets to it
		// go nowhere, so the connect neither succeeds nor is refused. Every
		// other bound is switched off; only DialTimeout can end this send.
		// (On a network that rejects the address at once the send fails at
		// once, which satisfies the test as well.)
		m := NewSMTPMailer(SMTPConfig{
			Host: "192.0.2.1", Port: 25, From: "noreply@example.com",
			DialTimeout: 300 * time.Millisecond, SendTimeout: -1,
		})
		err, took := sendWithin(t, 8*time.Second, m, context.Background(), testMessage)
		require.Error(t, err)
		assert.Less(t, took, 5*time.Second)
	})

	t.Run("an unreachable server is an error", func(t *testing.T) {
		srv := startFakeSMTP(t, fakeSMTPConfig{})
		port := srv.port()
		require.NoError(t, srv.ln.Close()) // nothing listens there any more

		m := NewSMTPMailer(SMTPConfig{Host: "127.0.0.1", Port: port, From: "noreply@example.com", AllowPlaintext: true})
		err, took := sendWithin(t, 15*time.Second, m, context.Background(), testMessage)
		require.Error(t, err)
		assert.Less(t, took, 12*time.Second, "bounded by the dial timeout")
	})
}

// --- header values ---------------------------------------------------------------

func TestSMTPRejectsLineBreaksInHeaders(t *testing.T) {
	srv := startFakeSMTP(t, fakeSMTPConfig{})
	allow := func(c *SMTPConfig) { c.AllowPlaintext = true }

	cases := map[string]Message{
		"subject with CRLF": {To: "rcpt@example.com", Subject: "hi\r\nBcc: victim@example.com", TextBody: "x"},
		"subject with LF":   {To: "rcpt@example.com", Subject: "hi\nBcc: victim@example.com", TextBody: "x"},
		"subject with CR":   {To: "rcpt@example.com", Subject: "hi\rBcc: victim@example.com", TextBody: "x"},
		"to with CRLF":      {To: "rcpt@example.com\r\nBcc: victim@example.com", Subject: "hi", TextBody: "x"},
		"to with LF":        {To: "rcpt@example.com\n", Subject: "hi", TextBody: "x"},
		"to with CR":        {To: "rcpt@example.com\r", Subject: "hi", TextBody: "x"},
	}
	for name, msg := range cases {
		err := send(t, mailerFor(srv, allow), msg)
		require.ErrorIs(t, err, ErrInvalidHeader, name)
	}

	// The configured sender is checked as well.
	m := mailerFor(srv, func(c *SMTPConfig) {
		c.AllowPlaintext = true
		c.From = "noreply@example.com\r\nBcc: victim@example.com"
	})
	require.ErrorIs(t, send(t, m, testMessage), ErrInvalidHeader)

	assert.Empty(t, srv.seen(), "a rejected message must not open a connection")

	// Line breaks in the body are ordinary content.
	require.NoError(t, send(t, mailerFor(srv, allow), Message{
		To: "rcpt@example.com", Subject: "hi", TextBody: "a\r\nBcc: not-a-header@example.com\r\nb",
	}))
	sess := srv.only()
	head, body, _ := strings.Cut(sess.data, "\n\n")
	assert.NotContains(t, head, "Bcc:")
	assert.Contains(t, body, "Bcc: not-a-header@example.com")
}
