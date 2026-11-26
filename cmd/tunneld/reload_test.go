package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/edgetcp"
	"github.com/Bazinga0o0/tunnel/internal/server/frontend"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/services"
)

const reloadSecret = "0123456789abcdef0123456789abcdef"

// noHolders answers every holder lookup with "none", so that a request the
// API lets through to the lookup is a 404 and one it refuses is a 403.
type noHolders struct{ services.PortReservations }

func (noHolders) OwnerTCPPort(context.Context, int) (int64, bool, error) { return 0, false, nil }

type reloadEnv struct {
	t       *testing.T
	path    string
	app     *app
	logs    *lockedLog
	api     *httptest.Server
	pool    *edgetcp.Pool
	keyB64  string
	secrets string
}

// newReloadEnv starts an app with one service ("svc") whose tcp_ports are
// ports, without a database: the service API runs on fake reservations.
func newReloadEnv(t *testing.T, ports string) *reloadEnv {
	t.Helper()
	e := &reloadEnv{t: t}
	e.keyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	dir := t.TempDir()
	e.secrets = filepath.ToSlash(filepath.Join(dir, "svc.secret"))
	require.NoError(t, os.WriteFile(e.secrets, []byte(reloadSecret), 0o600))
	e.path = filepath.Join(dir, "tunneld.yaml")
	e.write(ports, "127.0.0.1:0")
	cfg := loadFile(t, e.path)

	logger, logs := captureLog()
	e.logs = logs
	e.pool = edgetcp.NewPool(cfg.TCP.PortRange.Low, cfg.TCP.PortRange.High)
	e.pool.Exclude(serviceTCPPorts(cfg))
	apiSvcs, err := serviceAPIServices(cfg)
	require.NoError(t, err)
	h := services.NewAPI(apiSvcs, noHolders{}, nil, false, registry.New(), nil, logger)
	e.api = httptest.NewServer(h)
	t.Cleanup(e.api.Close)
	e.app = &app{cfg: cfg, current: cfg, logger: logger, tcpPool: e.pool, serviceAPI: h}
	return e
}

// write writes the config file with the service's tcp_ports and the
// metrics address (a section that needs a restart).
func (e *reloadEnv) write(ports, metrics string) {
	body := fmt.Sprintf(`domain: tunnel.test
listen: {tunnel_addr: "127.0.0.1:0", http_addr: "127.0.0.1:0"}
tls: {self_signed_hosts: [tunnel.test, "*.tunnel.test"]}
auth: {csrf_key: %q}
database: {url: "postgres://u:p@127.0.0.1:1/db"}
metrics: {addr: %q}
tcp: {enabled: true, port_range: {low: 19000, high: 19100}}
service_api: {addr: "127.0.0.1:9100"}
services:
  - name: svc
    subdomain: svc-a
    upstream: "http://127.0.0.1:8080"
    secret_file: %q
    tcp_ports: %s
`, e.keyB64, metrics, e.secrets, ports)
	require.NoError(e.t, os.WriteFile(e.path, []byte(body), 0o600))
}

// status is the status of GET holder of port, as the service.
func (e *reloadEnv) status(port int) int {
	e.t.Helper()
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/tcp-ports/%d/holder", e.api.URL, port), nil)
	require.NoError(e.t, err)
	req.Header.Set("Authorization", "Bearer "+reloadSecret)
	res, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode
}

// drawnAtRandom reports whether the pool hands out port to a client that
// asks for any port; it drains the pool (the range is small) and puts back
// what it drew.
func (e *reloadEnv) drawnAtRandom(port int) bool {
	var drawn []int
	for {
		p, err := e.pool.Allocate(0)
		if err != nil {
			break
		}
		drawn = append(drawn, p)
	}
	for _, p := range drawn {
		e.pool.Release(p)
	}
	return contains(drawn, port)
}

func contains(l []int, v int) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func loadFile(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := config.Load(path)
	require.NoError(t, err)
	return cfg
}

func TestReloadAddsAPort(t *testing.T) {
	e := newReloadEnv(t, "[19000]")
	require.Equal(t, 404, e.status(19000))
	require.Equal(t, 403, e.status(19001))
	require.True(t, e.drawnAtRandom(19001))

	e.write("[19000, 19001]", "127.0.0.1:0")
	e.app.reloadFromFile()

	assert.Equal(t, 404, e.status(19001), "the service may set the new port's holder")
	assert.False(t, e.drawnAtRandom(19001), "the new port is no longer drawn at random")
	assert.Contains(t, e.logs.String(), "service tcp_ports reloaded")
}

func TestReloadKeepsAPortAHolderTunnelUses(t *testing.T) {
	e := newReloadEnv(t, "[19000, 19001]")
	// A tunnel holds 19001, as the edge does while it runs.
	p, err := e.pool.Allocate(19001)
	require.NoError(t, err)
	require.Equal(t, 19001, p)

	e.write("[19000]", "127.0.0.1:0")
	e.app.reloadFromFile()

	assert.Equal(t, 403, e.status(19001), "the service no longer owns the port")
	assert.Equal(t, 404, e.status(19000))
	_, err = e.pool.Allocate(19001)
	assert.ErrorIs(t, err, edgetcp.ErrPortUnavailable, "the running tunnel still holds the port")
	e.pool.Release(19001)
	assert.True(t, e.drawnAtRandom(19001), "once free it is an ordinary pool port")
	assert.Contains(t, e.logs.String(), "stay open to tunnels that hold them")
}

func TestReloadInvalidConfigChangesNothing(t *testing.T) {
	e := newReloadEnv(t, "[19000]")

	// 25000 is outside tcp.port_range: Load refuses the file.
	e.write("[19000, 25000]", "127.0.0.1:0")
	e.app.reloadFromFile()
	assert.Contains(t, e.logs.String(), "config reload failed")
	assert.Equal(t, 403, e.status(25000))
	assert.Equal(t, 404, e.status(19000))

	// Not YAML at all.
	require.NoError(t, os.WriteFile(e.path, []byte("domain: [unclosed"), 0o600))
	e.app.reloadFromFile()
	assert.Equal(t, 404, e.status(19000))
	assert.False(t, e.drawnAtRandom(19000))

	// A file that is gone.
	require.NoError(t, os.Remove(e.path))
	e.app.reloadFromFile()
	assert.Equal(t, 404, e.status(19000))
}

func TestReloadIgnoresWhatNeedsARestart(t *testing.T) {
	e := newReloadEnv(t, "[19000]")
	e.write("[19000, 19002]", "127.0.0.1:9191")
	e.app.reloadFromFile()

	out := e.logs.String()
	assert.Contains(t, out, "requires a restart")
	assert.Contains(t, out, "section=metrics")
	assert.Equal(t, "127.0.0.1:0", e.app.current.Metrics.Address(), "the running config keeps its metrics address")
	assert.Equal(t, 404, e.status(19002), "the ports change is applied all the same")
}

// writeDirectory rewrites the config file with the given directory flow
// mapping on the service (the services entry is the file's last).
func (e *reloadEnv) writeDirectory(ports, metrics, directory string) {
	e.write(ports, metrics)
	f, err := os.OpenFile(e.path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(e.t, err)
	_, err = f.WriteString("    directory: " + directory + "\n")
	require.NoError(e.t, err)
	require.NoError(e.t, f.Close())
}

func TestReloadAppliesTheDirectory(t *testing.T) {
	e := newReloadEnv(t, "[19000]")
	e.app.directory = &frontend.Directory{}
	e.app.directory.Set(directoryEntries(e.app.cfg))
	require.Empty(t, e.app.directory.Entries(), "a service is not listed by default")

	e.writeDirectory("[19000]", "127.0.0.1:0", `{listed: true, title: Svc, description: "A service"}`)
	e.app.reloadFromFile()
	assert.Equal(t, []frontend.DirectoryEntry{{Name: "svc", Title: "Svc", Description: "A service", URL: "https://svc-a.tunnel.test"}},
		e.app.directory.Entries())
	assert.Contains(t, e.logs.String(), "service directory reloaded")
	assert.NotContains(t, e.logs.String(), "requires a restart", "the directory is live-reloadable")

	// Directory and tcp_ports change together; both apply.
	e.writeDirectory("[19000, 19001]", "127.0.0.1:0", `{listed: true, title: New}`)
	e.app.reloadFromFile()
	require.Len(t, e.app.directory.Entries(), 1)
	assert.Equal(t, "New", e.app.directory.Entries()[0].Title)
	assert.Equal(t, 404, e.status(19001))

	// Unlisting removes the entry.
	e.writeDirectory("[19000, 19001]", "127.0.0.1:0", `{listed: false, title: New}`)
	e.app.reloadFromFile()
	assert.Empty(t, e.app.directory.Entries())
	assert.Equal(t, 404, e.status(19001), "the ports stay as they were")

	// An invalid directory changes nothing.
	e.writeDirectory("[19000, 19001]", "127.0.0.1:0", `{listed: true}`)
	e.app.reloadFromFile()
	assert.Contains(t, e.logs.String(), "config reload failed")
	assert.Empty(t, e.app.directory.Entries())
}

func TestReloadKeepsTheDirectoryOfAServiceThatChangedOtherwise(t *testing.T) {
	e := newReloadEnv(t, "[19000]")
	e.app.directory = &frontend.Directory{}
	e.app.directory.Set(directoryEntries(e.app.cfg))

	// The upstream changes as well: the service needs a restart, and its
	// directory change waits for it.
	e.writeDirectory("[19000]", "127.0.0.1:0", `{listed: true, title: Svc}`)
	b, err := os.ReadFile(e.path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(e.path, bytes.ReplaceAll(b, []byte("8080"), []byte("8081")), 0o600))
	e.app.reloadFromFile()
	assert.Contains(t, e.logs.String(), "requires a restart")
	assert.Empty(t, e.app.directory.Entries())
}
