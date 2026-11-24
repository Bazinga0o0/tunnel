package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tunnel.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func warningKinds(cfg *Config) []WarningKind {
	kinds := []WarningKind{}
	for _, w := range cfg.Warnings {
		kinds = append(kinds, w.Kind)
	}
	return kinds
}

func TestClientConfigLoad(t *testing.T) {
	path := writeConfig(t, `
server: tunnel.example.org:7443
token: twbl_abc
insecure_skip_verify: true
`)

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "tunnel.example.org:7443", cfg.Server)
	assert.Equal(t, "twbl_abc", cfg.Token)
	assert.True(t, cfg.InsecureSkipVerify)
	assert.Empty(t, cfg.CAFile)
}

func TestClientConfigMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	require.ErrorIs(t, err, ErrMissingFile)
}

func TestClientConfigRejectsEmptyServer(t *testing.T) {
	path := writeConfig(t, "token: twbl_abc")

	_, err := Load(path)
	require.ErrorIs(t, err, ErrNotConfigured)
}

func TestLoadVerificationIsOnByDefault(t *testing.T) {
	path := writeConfig(t, "server: tunnel.example.org:7443\ntoken: twbl_abc\n")

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.False(t, cfg.InsecureSkipVerify)
	assert.NotContains(t, warningKinds(cfg), WarnInsecureSkipVerify)
}

// The example file is part of every client archive. It must be a usable
// config that leaves certificate verification on.
func TestShippedExampleConfigKeepsVerificationOn(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "..", "configs", "tunnel.example.yaml"))
	require.NoError(t, err)
	assert.False(t, cfg.InsecureSkipVerify)
	assert.Empty(t, cfg.CAFile)
	assert.NotContains(t, warningKinds(cfg), WarnInsecureSkipVerify)
}

func TestLoadWarnsWhenVerificationIsOff(t *testing.T) {
	path := writeConfig(t, "server: tunnel.example.org:7443\ntoken: twbl_secret_value\ninsecure_skip_verify: true\n")

	cfg, err := Load(path)
	require.NoError(t, err)
	require.Contains(t, warningKinds(cfg), WarnInsecureSkipVerify)
	for _, w := range cfg.Warnings {
		assert.NotEmpty(t, w.Message)
		assert.NotContains(t, w.Message, "twbl_secret_value", "a warning must never repeat the token")
	}
}

func TestLoadKeepsAbsoluteCAFile(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "pki", "ca.pem")
	path := writeConfig(t, "server: s:1\ntoken: t\nca_file: "+quoteYAML(abs)+"\n")

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, abs, cfg.CAFile)
}

func TestLoadResolvesRelativeCAFileAgainstConfigDir(t *testing.T) {
	path := writeConfig(t, "server: s:1\ntoken: t\nca_file: pki/ca.pem\n")

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(filepath.Dir(path), "pki", "ca.pem"), cfg.CAFile)
}

// quoteYAML wraps a path in single quotes so that Windows backslashes and
// drive colons survive YAML parsing.
func quoteYAML(s string) string { return "'" + s + "'" }

func TestPermissionWarning(t *testing.T) {
	cases := []struct {
		name string
		goos string
		mode fs.FileMode
		want bool
	}{
		{"linux owner only", "linux", 0o600, false},
		{"linux owner read only", "linux", 0o400, false},
		{"linux group readable", "linux", 0o640, true},
		{"linux others readable", "linux", 0o604, true},
		{"linux world readable", "linux", 0o644, true},
		{"linux group writable only", "linux", 0o620, true},
		{"linux others executable only", "linux", 0o601, true},
		{"darwin world readable", "darwin", 0o644, true},
		{"darwin owner only", "darwin", 0o600, false},
		// Windows reports 0666 for every writable file; the bits say nothing
		// about who may read it, so they are not judged there.
		{"windows default mode", "windows", 0o666, false},
		{"windows read-only mode", "windows", 0o444, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, ok := permissionWarning(tc.goos, tc.mode, "/home/u/.config/tunnel/config.yaml")
			assert.Equal(t, tc.want, ok)
			if tc.want {
				assert.Equal(t, WarnConfigPermissions, w.Kind)
				assert.Contains(t, w.Message, "/home/u/.config/tunnel/config.yaml")
			} else {
				assert.Equal(t, Warning{}, w)
			}
		})
	}
}

func TestLoadWarnsAboutReadableConfigFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows")
	}
	path := writeConfig(t, "server: s:1\ntoken: t\n")

	require.NoError(t, os.Chmod(path, 0o644))
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Contains(t, warningKinds(cfg), WarnConfigPermissions)

	require.NoError(t, os.Chmod(path, 0o600))
	cfg, err = Load(path)
	require.NoError(t, err)
	assert.NotContains(t, warningKinds(cfg), WarnConfigPermissions)
}

func TestLoadDoesNotJudgePermissionsOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	path := writeConfig(t, "server: s:1\ntoken: t\n")

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Empty(t, cfg.Warnings)
}

func TestDefaultPath(t *testing.T) {
	p, err := DefaultPath()
	require.NoError(t, err)
	assert.NotEmpty(t, p)
	assert.Contains(t, p, "tunnel")
}

func TestEnsureTemplateCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "tunnel.yaml")
	created, err := EnsureTemplate(path)
	require.NoError(t, err)
	assert.True(t, created)

	body, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(body), "server: \"\"\n")
	assert.Contains(t, string(body), "token: \"\"\n")
	assert.Contains(t, string(body), "insecure_skip_verify: false\n")
	assert.Contains(t, string(body), "ca_file")

	// The template is a valid, not yet configured config.
	_, err = Load(path)
	require.ErrorIs(t, err, ErrNotConfigured)
}

func TestEnsureTemplateFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows")
	}
	path := filepath.Join(t.TempDir(), "sub", "tunnel.yaml")
	_, err := EnsureTemplate(path)
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), info.Mode().Perm())
	dirInfo, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o700), dirInfo.Mode().Perm())
}

func TestEnsureTemplateSkipsIfExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunnel.yaml")
	require.NoError(t, os.WriteFile(path, []byte("already here"), 0o600))

	created, err := EnsureTemplate(path)
	require.NoError(t, err)
	assert.False(t, created)

	body, _ := os.ReadFile(path)
	assert.Equal(t, "already here", string(body))
}

// A symlink planted at the config path must not be written through: the old
// stat-then-write sequence followed it and created the link's target.
func TestEnsureTemplateDoesNotWriteThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.txt")
	path := filepath.Join(dir, "tunnel.yaml")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	created, err := EnsureTemplate(path)
	require.Error(t, err)
	assert.False(t, created)

	_, statErr := os.Lstat(target)
	assert.ErrorIs(t, statErr, fs.ErrNotExist, "the symlink target must not have been created")
}

func TestEnsureTemplateRejectsDirectoryAtPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunnel.yaml")
	require.NoError(t, os.Mkdir(path, 0o700))

	created, err := EnsureTemplate(path)
	require.Error(t, err)
	assert.False(t, created)
}

// Exactly one of several concurrent callers creates the file; nobody
// overwrites what the winner wrote.
func TestEnsureTemplateConcurrentCallersCreateOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunnel.yaml")

	const callers = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created int
		start   = make(chan struct{})
	)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := EnsureTemplate(path)
			assert.NoError(t, err)
			if ok {
				mu.Lock()
				created++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	assert.Equal(t, 1, created)
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, Template, string(body))
}
