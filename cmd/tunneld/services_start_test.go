package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/audit"
	"github.com/Bazinga0o0/tunnel/internal/server/auth"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/tokens"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// keepSystemReserved restores the system-reserved names after the test: the
// start-up adds the subdomains of the services to that process-wide list.
func keepSystemReserved(t *testing.T) {
	t.Helper()
	prev := slices.Clone(reservations.SystemReservedNames)
	t.Cleanup(func() { reservations.SystemReservedNames = prev })
}

// The admin CLI keeps the subdomains of the
// registered services from reservations, as the server does. The command the
// start-up warning names still releases an older reservation of one.
func TestAdminCLIKnowsTheServiceSubdomains(t *testing.T) {
	keepSystemReserved(t)
	c := newAdminCLITest(t)
	ctx := context.Background()
	owner := dbtest.InsertUser(t, c.pool, "owner@example.com")
	// Made before the service was added to the config.
	require.NoError(t, c.res.GrantSubdomain(ctx, "svc-older", owner))

	body, err := os.ReadFile(c.cfgPath)
	require.NoError(t, err)
	body = append(body, []byte(`services:
  - name: newer
    subdomain: svc-newer
    upstream: "http://127.0.0.1:8080"
    secret_file: /etc/tunneld/services/newer.secret
  - name: older
    subdomain: svc-older
    upstream: "http://127.0.0.1:8081"
    secret_file: /etc/tunneld/services/older.secret
`)...)
	c.cfgPath = filepath.Join(t.TempDir(), "with-services.yaml")
	require.NoError(t, os.WriteFile(c.cfgPath, body, 0o600))

	r := c.run(t, cliOptions{}, "reserve-subdomain", "--email", "owner@example.com", "--subdomain", "svc-newer")
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "reserved for system use")
	_, reserved, err := c.res.Owner(ctx, "svc-newer")
	require.NoError(t, err)
	assert.False(t, reserved)

	r = c.mustRun(t, cliOptions{}, "release-subdomain", "--subdomain", "svc-older")
	assert.Contains(t, r.out, `"released": true`)
	_, reserved, err = c.res.Owner(ctx, "svc-older")
	require.NoError(t, err)
	assert.False(t, reserved)
}

// At start-up the server warns about
// a reservation of a service port, which lets its account host there until
// the service changes the holder, and names the account. The warning about a
// reserved service subdomain names a complete command, with the config.
func TestOpenServicesWarnsAboutReservedServicePorts(t *testing.T) {
	keepSystemReserved(t)
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	res := reservations.NewService(pool)
	owner := dbtest.InsertUser(t, pool, "owner@example.com")
	portOwner := dbtest.InsertUser(t, pool, "port-owner@example.com")
	require.NoError(t, res.GrantSubdomain(ctx, "svc-warn", owner))
	require.NoError(t, res.GrantTCPPort(ctx, 19000, portOwner))

	secretFile := filepath.Join(t.TempDir(), "svc.secret")
	require.NoError(t, os.WriteFile(secretFile, []byte(strings.Repeat("s", 40)), 0o600))
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	cfg := loadConfig(t, fmt.Sprintf(`domain: tunnel.test
listen: {tunnel_addr: "127.0.0.1:0", http_addr: "127.0.0.1:0"}
tls: {self_signed_hosts: [tunnel.test]}
auth: {csrf_key: %q}
database: {url: %q}
tcp: {enabled: true, port_range: {low: 19000, high: 20000}}
service_api: {addr: "127.0.0.1:9100"}
services:
  - name: svc
    subdomain: svc-warn
    upstream: "http://127.0.0.1:8080"
    secret_file: %q
    tcp_ports: [19000, 19001]
`, key, os.Getenv("TUNNELD_TEST_DATABASE_URL"), filepath.ToSlash(secretFile)))
	require.NotEmpty(t, cfg.Path)

	logger, logs := captureLog()
	userSvc := users.NewService(pool)
	a := &app{cfg: cfg, logger: logger, reg: registry.New(), users: userSvc, reservations: res}
	require.NoError(t, a.openServices(ctx, auth.NewDBVerifier(tokens.NewService(pool)), audit.NewService(pool)))

	var portLines, subdomainLines []string
	for _, line := range strings.Split(logs.String(), "\n") {
		switch {
		case strings.Contains(line, "service port is reserved"):
			portLines = append(portLines, line)
		case strings.Contains(line, "service subdomain is reserved"):
			subdomainLines = append(subdomainLines, line)
		}
	}
	require.Len(t, portLines, 1, "one warning, for the reserved port only: %s", logs.String())
	assert.Contains(t, portLines[0], "level=WARN")
	assert.Contains(t, portLines[0], "port=19000")
	assert.Contains(t, portLines[0], fmt.Sprintf("user_id=%d", portOwner))
	assert.Contains(t, portLines[0], "DELETE /v1/tcp-ports/19000/holder")
	assert.Contains(t, portLines[0], "admin panel")

	require.Len(t, subdomainLines, 1, logs.String())
	assert.Contains(t, subdomainLines[0], fmt.Sprintf("user_id=%d", owner))
	// The log quotes the message and doubles a backslash (a Windows path).
	command := "tunneld admin release-subdomain --config " + shellWord(cfg.Path) + " --subdomain svc-warn"
	assert.Contains(t, subdomainLines[0], strings.ReplaceAll(command, `\`, `\\`))
}

func TestConfigArgForTheWarnings(t *testing.T) {
	for path, want := range map[string]string{
		"":                          "PATH",
		"/etc/tunneld/config.yaml":  "/etc/tunneld/config.yaml",
		`C:\tunneld\config.yaml`:    `'C:\tunneld\config.yaml'`,
		"/srv/my config/tunnel.yml": "'/srv/my config/tunnel.yml'",
		"/srv/it's/config.yaml":     `'/srv/it'\''s/config.yaml'`,
	} {
		assert.Equal(t, want, configArg(path), path)
	}
}
