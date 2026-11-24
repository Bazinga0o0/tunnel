package config

import (
	"fmt"
	"io/fs"
	"net"
)

// fileModeWarning returns a warning when other users can access the config
// file, which holds secrets. Access by the group is expected: the installer
// makes the file root:tunneld 0640. On Windows the mode bits do not describe
// the access rights, so there is no check.
func fileModeWarning(goos, path string, mode fs.FileMode) string {
	if goos == "windows" || mode.Perm()&0o007 == 0 {
		return ""
	}
	return fmt.Sprintf("config file %s is accessible by other users (mode %04o); "+
		"it holds secrets such as the database password, restrict it to 0640 (root:tunneld) or 0600",
		path, mode.Perm())
}

// startupWarnings returns the warnings about settings that are allowed but
// risky.
func (c *Config) startupWarnings() []string {
	var out []string
	if len(c.TLS.SelfSignedHosts) > 0 && c.Database.URL != "" {
		out = append(out, "tls: the self-signed certificate is in use together with database.url; "+
			"browsers and tunnel clients cannot verify it. Configure tls.acme or tls.cert_file for production")
	}
	if c.Mail.SMTP.AllowPlaintext {
		out = append(out, "mail.smtp.allow_plaintext is set: mail is sent without TLS when the SMTP server offers no STARTTLS; "+
			"use it only for a mail catcher on this machine")
	}
	if addr := c.Metrics.Address(); addr != "" && c.Metrics.AllowNonLoopback {
		if host, _, err := net.SplitHostPort(addr); err == nil && !isLoopbackHost(host) {
			out = append(out, fmt.Sprintf("metrics.addr %q is reachable from other hosts and the endpoint has no authentication", addr))
		}
	}
	out = append(out, c.disabledProtectionWarnings()...)
	return out
}
