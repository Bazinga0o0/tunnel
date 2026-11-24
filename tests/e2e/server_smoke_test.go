package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/testports"
)

// startupWait bounds the wait for the server's "listening" line. It ends as
// soon as the line appears; the generous value keeps a loaded machine from
// failing the test.
const startupWait = 2 * time.Minute

var (
	buildOnce sync.Once
	binDir    string // removed by TestMain
	binPath   string
	buildErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// buildTunneld compiles cmd/tunneld once per test run into a temporary
// directory and returns the binary.
//
// Building first and running the binary, rather than `go run`, matters on
// Windows: `go run` starts the server as a grandchild that killing the go
// process does not stop, and that keeps the output pipes open.
func buildTunneld(t *testing.T, root string) string {
	t.Helper()
	buildOnce.Do(func() {
		binDir, buildErr = os.MkdirTemp("", "tunneld-e2e-")
		if buildErr != nil {
			return
		}
		name := "tunneld"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		binPath = filepath.Join(binDir, name)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		build := exec.CommandContext(ctx, "go", "build", "-o", binPath, "./cmd/tunneld")
		build.Dir = root
		if out, err := build.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("%w\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatalf("build failed: %v", buildErr)
	}
	return binPath
}

// lineWatcher collects the output of the server and reports when a line
// containing a given text appears.
type lineWatcher struct {
	mu    sync.Mutex
	lines []string
	seen  chan struct{}
	want  string
	once  sync.Once
}

func (w *lineWatcher) consume(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		w.mu.Lock()
		w.lines = append(w.lines, line)
		w.mu.Unlock()
		if strings.Contains(line, w.want) {
			w.once.Do(func() { close(w.seen) })
		}
	}
}

func (w *lineWatcher) output() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.Join(w.lines, "\n")
}

// TestServerBinaryStartsAndListens builds cmd/tunneld, runs `tunneld serve`
// with a config on free loopback ports, waits for the listen banner and then
// talks to all three listeners.
func TestServerBinaryStartsAndListens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	binPath := buildTunneld(t, root)

	low, _ := testports.FreeTCPRange(t, 3)
	tunnelAddr := net.JoinHostPort(testports.Loopback, strconv.Itoa(low))
	httpAddr := net.JoinHostPort(testports.Loopback, strconv.Itoa(low+1))
	metricsAddr := net.JoinHostPort(testports.Loopback, strconv.Itoa(low+2))
	cfg := fmt.Sprintf(`domain: tunnel.localhost
listen:
  tunnel_addr: %q
  http_addr: %q
metrics:
  addr: %q
tls:
  self_signed_hosts:
    - tunnel.localhost
    - "*.tunnel.localhost"
auth:
  tokens:
    - twbl_smoke_token_0001
`, tunnelAddr, httpAddr, metricsAddr)
	cfgPath := filepath.Join(t.TempDir(), "tunneld.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o600))

	cmd := exec.Command(binPath, "serve", "--config", cfgPath)
	cmd.Dir = root
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = cmd.Stdout
	require.NoError(t, cmd.Start())
	exited := make(chan error, 1)
	watcher := &lineWatcher{seen: make(chan struct{}), want: "tunneld listening"}
	go func() {
		watcher.consume(stdout)
		exited <- cmd.Wait()
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-exited:
		case <-time.After(30 * time.Second):
			t.Error("the server process did not end after it was killed")
		}
	})

	select {
	case <-watcher.seen:
	case err := <-exited:
		t.Fatalf("server exited before listening: %v\n%s", err, watcher.output())
	case <-time.After(startupWait):
		t.Fatalf("no listen banner after %s:\n%s", startupWait, watcher.output())
	}
	out := watcher.output()
	assert.Contains(t, out, "tls source: self-signed")
	assert.Contains(t, out, "metrics endpoint enabled")

	tlsClient := &tls.Config{InsecureSkipVerify: true}

	// The tunnel listener completes a TLS handshake.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", tunnelAddr, tlsClient)
	require.NoError(t, err, "tunnel listener")
	_ = conn.Close()

	// The public listener answers; an unknown tunnel is a 404 from the edge.
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: tlsClient,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, httpAddr)
		},
	}}
	res, err := client.Get("https://nothing.tunnel.localhost/")
	require.NoError(t, err, "public listener")
	_ = res.Body.Close()
	assert.Equal(t, http.StatusNotFound, res.StatusCode)

	// The metrics endpoint serves the metrics.
	res, err = (&http.Client{Timeout: 30 * time.Second}).Get("http://" + metricsAddr + "/_tunneld/metrics")
	require.NoError(t, err, "metrics endpoint")
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, string(body), "tunneld_cert_not_after_unix")
}

func TestServerBinaryPrintsItsVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	binPath := buildTunneld(t, root)

	ctx, cancel := context.WithTimeout(context.Background(), startupWait)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, "version").CombinedOutput()
	require.NoError(t, err, "%s", out)
	assert.Equal(t, "tunneld dev (commit none, built unknown)\n", strings.ReplaceAll(string(out), "\r\n", "\n"))
}

// A config that the server refuses ends the start with the error, not with a
// half-started server.
func TestServerBinaryRefusesAnUnknownConfigKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	binPath := buildTunneld(t, root)

	cfgPath := filepath.Join(t.TempDir(), "tunneld.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`domain: tunnel.localhost
listen: {tunnel_addr: "127.0.0.1:0", http_addr: "127.0.0.1:0"}
tls: {self_signed_hosts: [tunnel.localhost]}
auth: {tokens: [twbl_smoke_token_0001]}
metrics: {addr: ""}
tunel: {max_sessions: 5}
`), 0o600))
	ctx, cancel := context.WithTimeout(context.Background(), startupWait)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, "serve", "--config", cfgPath).CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, string(out), "tunel")
	assert.NotContains(t, string(out), "tunneld listening")
}
