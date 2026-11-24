package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ---- mail settings are checked when mail is on ----

const smtpSection = "mail:\n  from: \"noreply@example.org\"\n  smtp:\n    host: \"smtp.example.org\"\n    port: 587\n"

func TestMailSettingsAreValidatedWhenSMTPIsSet(t *testing.T) {
	mustLoad(t, staticBase+smtpSection)
	for name, tc := range map[string]struct{ from, port, want string }{
		"port missing":        {"noreply@example.org", "0", "mail.smtp.port"},
		"port negative":       {"noreply@example.org", "-1", "mail.smtp.port"},
		"port too large":      {"noreply@example.org", "65536", "mail.smtp.port"},
		"from missing":        {"", "587", "mail.from"},
		"from not an address": {"noreply", "587", "mail.from"},
		"from with a name":    {"Tunnel <noreply@example.org>", "587", "mail.from"},
		"from with two":       {"a@example.org, b@example.org", "587", "mail.from"},
	} {
		t.Run(name, func(t *testing.T) {
			body := staticBase + "mail:\n  from: \"" + tc.from + "\"\n  smtp:\n    host: \"smtp.example.org\"\n    port: " + tc.port + "\n"
			err := requireRefused(t, body, tc.want)
			if tc.from != "" {
				// Config errors name the key and the rule, never the value.
				assert.NotContains(t, err.Error(), tc.from)
			}
		})
	}
	for _, port := range []string{"1", "25", "465", "65535"} {
		mustLoad(t, staticBase+strings.Replace(smtpSection, "587", port, 1))
	}
	// Without an SMTP host mail is off: port and sender are not needed.
	mustLoad(t, staticBase+"mail:\n  queue_size: 10\n")
}

// A negative send timeout would leave the mail workers without any bound.
// A negative dial timeout leaves the connect to the send timeout, which is
// bounded.
func TestNegativeSMTPSendTimeoutIsRefused(t *testing.T) {
	requireRefused(t, staticBase+smtpSection+"    send_timeout: -1s\n", "mail.smtp.send_timeout")
	cfg := mustLoad(t, staticBase+smtpSection+"    dial_timeout: -1s\n")
	assert.Equal(t, -time.Second, cfg.Mail.SMTP.DialTimeout)
}
