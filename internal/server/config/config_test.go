package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	body := `
domain: tunnel.localhost
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  cert_file: ""
  key_file: ""
  self_signed_hosts:
    - tunnel.localhost
    - "*.localhost"
auth:
  tokens:
    - twbl_devtoken_0001
    - twbl_devtoken_0002
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "tunnel.localhost", cfg.Domain)
	assert.Equal(t, ":7443", cfg.Listen.TunnelAddr)
	assert.Equal(t, ":443", cfg.Listen.HTTPAddr)
	assert.Equal(t, []string{"tunnel.localhost", "*.localhost"}, cfg.TLS.SelfSignedHosts)
	assert.Len(t, cfg.Auth.Tokens, 2)
}

func TestLoadRejectsMissingDomain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	require.NoError(t, os.WriteFile(path, []byte("listen: {tunnel_addr: \":7443\"}"), 0o600))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "domain")
}

func TestLoadRejectsEmptyTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	body := `
domain: tunnel.localhost
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [tunnel.localhost]
auth:
  tokens: []
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one of database.url or auth.tokens")
}

func TestLoadRejectsBothDatabaseAndTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	body := `
domain: tunnel.localhost
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [tunnel.localhost]
auth:
  tokens: [twbl_devtoken_0001]
database:
  url: "postgres://tunneld:tunneld_dev_password@127.0.0.1:5432/tunneld?sslmode=disable"
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one of database.url or auth.tokens")
}

func TestLoadAcceptsDatabaseOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	body := `
domain: tunnel.localhost
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [tunnel.localhost]
auth:
  csrf_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
database:
  url: "postgres://tunneld:tunneld_dev_password@127.0.0.1:5432/tunneld?sslmode=disable"
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Contains(t, cfg.Database.URL, "127.0.0.1:5432")
	assert.Empty(t, cfg.Auth.Tokens)
	assert.Len(t, cfg.CSRFKeyBytes(), 32)
}

func TestLoadParsesDatabaseURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	body := `
domain: tunnel.localhost
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [tunnel.localhost]
auth:
  csrf_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
database:
  url: "postgres://tunneld:tunneld_dev_password@127.0.0.1:5432/tunneld?sslmode=disable"
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Contains(t, cfg.Database.URL, "127.0.0.1:5432")
	// Sanity: the example key decodes to exactly 32 bytes.
	assert.Len(t, cfg.CSRFKeyBytes(), 32)
}

func TestLoadRejectsDatabaseWithoutCSRFKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	body := `
domain: tunnel.localhost
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [tunnel.localhost]
database:
  url: "postgres://tunneld:tunneld_dev_password@127.0.0.1:5432/tunneld?sslmode=disable"
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "csrf_key is required")
}

func TestLoadRejectsInvalidBase64CSRFKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	body := `
domain: tunnel.localhost
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [tunnel.localhost]
auth:
  csrf_key: "not-valid-base64!!!"
database:
  url: "postgres://tunneld:tunneld_dev_password@127.0.0.1:5432/tunneld?sslmode=disable"
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base64")
}

func TestLoadAcceptsACMEConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	body := `
domain: example.org
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  acme:
    email: "ops@example.org"
    dns_provider: "ionos"
    domains:
      - "example.org"
      - "*.example.org"
    cache_dir: "/var/lib/tunneld/certs"
    staging: true
auth:
  csrf_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
database:
  url: "postgres://tunneld:tunneld_dev_password@127.0.0.1:5432/tunneld?sslmode=disable"
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg.TLS.ACME)
	assert.Equal(t, "ops@example.org", cfg.TLS.ACME.Email)
	assert.Equal(t, "ionos", cfg.TLS.ACME.DNSProvider)
	assert.Equal(t, []string{"example.org", "*.example.org"}, cfg.TLS.ACME.Domains)
	assert.Equal(t, "/var/lib/tunneld/certs", cfg.TLS.ACME.CacheDir)
	assert.True(t, cfg.TLS.ACME.Staging)
}

func TestLoadRejectsMultipleTLSSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	body := `
domain: example.org
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [example.org]
  acme:
    email: "ops@example.org"
    dns_provider: "ionos"
    domains: ["example.org"]
    cache_dir: "/var/lib/tunneld/certs"
auth:
  tokens: [twbl_devtoken_0001]
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only one of tls.cert_file")
}

func TestLoadRejectsACMEMissingDomains(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	body := `
domain: example.org
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  acme:
    email: "ops@example.org"
    dns_provider: "ionos"
    cache_dir: "/var/lib/tunneld/certs"
auth:
  tokens: [twbl_devtoken_0001]
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls.acme.domains")
}

func TestLoadParsesMailSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	body := `
domain: tunnel.localhost
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [tunnel.localhost]
auth:
  csrf_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
database:
  url: "postgres://tunneld:tunneld_dev_password@127.0.0.1:5432/tunneld?sslmode=disable"
mail:
  from: "noreply@example.org"
  smtp:
    host: "127.0.0.1"
    port: 1025
    username: "smtp-user"
    password: "smtp-pass"
    auth_required: true
frontend:
  public_base_url: "https://app.example.org"
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "noreply@example.org", cfg.Mail.From)
	assert.Equal(t, "127.0.0.1", cfg.Mail.SMTP.Host)
	assert.Equal(t, 1025, cfg.Mail.SMTP.Port)
	assert.Equal(t, "smtp-user", cfg.Mail.SMTP.Username)
	assert.Equal(t, "smtp-pass", cfg.Mail.SMTP.Password)
	assert.True(t, cfg.Mail.SMTP.AuthRequired)
	assert.Equal(t, "https://app.example.org", cfg.Frontend.PublicBaseURL)
}

func TestLoadRejectsShortCSRFKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	// "c2hvcnQ=" decodes to "short" (5 bytes), well under the required 32.
	body := `
domain: tunnel.localhost
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [tunnel.localhost]
auth:
  csrf_key: "c2hvcnQ="
database:
  url: "postgres://tunneld:tunneld_dev_password@127.0.0.1:5432/tunneld?sslmode=disable"
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestUDPDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	body := `
domain: tunnel.localhost
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [tunnel.localhost]
auth:
  tokens: [twbl_devtoken_0001]
udp:
  enabled: true
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.True(t, cfg.UDP.Enabled)
	assert.Equal(t, 30000, cfg.UDP.PortRange.Low)
	assert.Equal(t, 40000, cfg.UDP.PortRange.High)
	assert.Equal(t, 30*time.Second, cfg.UDP.FlowIdleTimeout)
	assert.Equal(t, 64, cfg.UDP.FlowBufferSize)
}

func TestUDPRangeValidation(t *testing.T) {
	base := `
domain: tunnel.localhost
listen:
  tunnel_addr: ":7443"
  http_addr: ":443"
tls:
  self_signed_hosts: [tunnel.localhost]
auth:
  tokens: [twbl_devtoken_0001]
udp:
  enabled: true
`
	cases := []struct {
		name string
		udp  string
	}{
		{"low > high", "  port_range:\n    low: 40000\n    high: 30000\n"},
		{"low < 1", "  port_range:\n    low: 0\n    high: 40000\n"},
		{"high > 65535", "  port_range:\n    low: 30000\n    high: 70000\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "tunneld.yaml")
			require.NoError(t, os.WriteFile(path, []byte(base+tc.udp), 0o600))
			_, err := Load(path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "udp")
		})
	}
}
