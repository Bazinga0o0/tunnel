package config

import (
	"errors"
	"net/mail"
)

// validateMail checks the mail settings. With mail.smtp.host set every mail
// goes to that server, so a port out of range or a missing or malformed
// sender would make every mail fail in the background queue, with no more
// than a log line: verification and reset mails would never arrive.
func (c *Config) validateMail() error {
	m := c.Mail
	if m.QueueSize < 0 {
		return errors.New("config: mail.queue_size must not be negative")
	}
	// Without a deadline of its own a delivery would be bounded by nothing
	// at all. A negative dial timeout is fine: the connect is then bounded
	// by the send timeout.
	if m.SMTP.SendTimeout < 0 {
		return errors.New("config: mail.smtp.send_timeout must not be negative (zero selects 30s)")
	}
	if m.SMTP.Host == "" {
		return nil
	}
	if m.SMTP.Port < 1 || m.SMTP.Port > 65535 {
		return errors.New("config: mail.smtp.port must be from 1 to 65535 when mail.smtp.host is set")
	}
	if m.From == "" {
		return errors.New("config: mail.from is required when mail.smtp.host is set")
	}
	// The sender goes into MAIL FROM as it is: a bare address, without a
	// display name or angle brackets.
	if a, err := mail.ParseAddress(m.From); err != nil || a.Name != "" || a.Address != m.From {
		return errors.New("config: mail.from must be a plain e-mail address (name@example.com), without a display name")
	}
	return nil
}
