// Package config loads the tunnel client's configuration file.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server             string `yaml:"server"`
	Token              string `yaml:"token"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`

	// CAFile is the path of a PEM file with the CA certificate(s) that issued
	// the server's certificate, for servers with a private CA. When it is set
	// the server certificate must chain to a CA in this file; the system
	// trust store is not consulted. A relative path is resolved against the
	// directory of the config file by Load.
	CAFile string `yaml:"ca_file"`

	// Warnings lists what Load found worth telling the user about (for
	// example: certificate verification is switched off). Load only collects
	// them; the caller decides where to print them.
	Warnings []Warning `yaml:"-"`
}

// WarningKind identifies the reason for a Warning.
type WarningKind string

const (
	// WarnInsecureSkipVerify: the config switches TLS certificate
	// verification off.
	WarnInsecureSkipVerify WarningKind = "insecure_skip_verify"
	// WarnConfigPermissions: the config file, which holds the API token, can
	// be accessed by other local users.
	WarnConfigPermissions WarningKind = "config_permissions"
)

// Warning is a non-fatal finding of Load.
type Warning struct {
	Kind    WarningKind
	Message string
}

// ErrNotConfigured is returned by Load when the config file exists but is
// blank or missing required fields. Callers can present a tailored help
// message and exit.
var ErrNotConfigured = errors.New("config is present but missing required fields (server + token)")

// ErrMissingFile is returned by Load when the config file doesn't exist.
var ErrMissingFile = errors.New("config file not found")

// Template is the YAML written by EnsureTemplate / `tunnel config init`.
const Template = `# tunnel client config
#
# Get a token from your tunnel server's web UI (/tokens) and paste it below.
# Then run: tunnel http 8080
#
# The "server" field is host:port of the tunnel control endpoint.
# For a self-hosted tunneld: tunnel.yourdomain.com:7443
#
# insecure_skip_verify switches the check of the server's TLS certificate off.
# Anyone on the network path can then read your token and your traffic, and
# the client prints a warning on every start. Use it only for a local dev
# server with a throw-away self-signed certificate.
#
# For a server whose certificate comes from a private CA, leave
# insecure_skip_verify at false and point ca_file at the CA certificate (PEM):
#   ca_file: /path/to/ca.pem

server: ""
token: ""
insecure_skip_verify: false
`

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrMissingFile
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Server == "" || cfg.Token == "" {
		return nil, ErrNotConfigured
	}
	if cfg.CAFile != "" && !filepath.IsAbs(cfg.CAFile) {
		cfg.CAFile = filepath.Join(filepath.Dir(path), cfg.CAFile)
	}

	if cfg.InsecureSkipVerify {
		cfg.Warnings = append(cfg.Warnings, Warning{
			Kind: WarnInsecureSkipVerify,
			Message: "TLS certificate verification is disabled (insecure_skip_verify: true). " +
				"The server's identity is not checked; anyone on the network path can read " +
				"the API token and the tunnelled traffic. For a server with a private CA " +
				"use ca_file instead.",
		})
	}
	if info, err := os.Stat(path); err == nil {
		if w, ok := permissionWarning(runtime.GOOS, info.Mode(), path); ok {
			cfg.Warnings = append(cfg.Warnings, w)
		}
	}
	return &cfg, nil
}

// permissionWarning reports whether a config file with the given mode is
// accessible to the group or to others. The file holds the API token, so on
// Unix it should be 0600. Windows does not express access through these bits
// (every writable file reports 0666), so nothing is judged there.
func permissionWarning(goos string, mode fs.FileMode, path string) (Warning, bool) {
	if goos == "windows" {
		return Warning{}, false
	}
	if mode.Perm()&0o077 == 0 {
		return Warning{}, false
	}
	return Warning{
		Kind: WarnConfigPermissions,
		Message: fmt.Sprintf("config file %s has mode %04o and can be accessed by other users; "+
			"it holds your API token. Restrict it with: chmod 600 %s", path, mode.Perm(), path),
	}, true
}

// EnsureTemplate writes Template to path if nothing is there yet. Creates
// parent directories as needed. Returns (created bool, err).
//
// The file is created exclusively (O_CREATE|O_EXCL): an existing file is
// never overwritten, also not when it appears between a check and the write,
// and a symlink at path is not followed. If path exists but is not a regular
// file, an error is returned instead of reporting "already there".
func EnsureTemplate(path string) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, fmt.Errorf("mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		info, statErr := os.Lstat(path)
		if statErr == nil && info.Mode().IsRegular() {
			return false, nil
		}
		if statErr == nil {
			return false, fmt.Errorf("write template: %s exists and is not a regular file", path)
		}
		return false, fmt.Errorf("write template: %w", err)
	}
	if _, err := f.WriteString(Template); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("write template: %w", err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("write template: %w", err)
	}
	return true, nil
}

// DefaultPath returns the OS-specific default config path.
// Linux/macOS: $XDG_CONFIG_HOME/tunnel/config.yaml or ~/.config/tunnel/config.yaml
// Windows:    %APPDATA%\tunnel\config.yaml
func DefaultPath() (string, error) {
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", fmt.Errorf("APPDATA not set")
		}
		return filepath.Join(appdata, "tunnel", "config.yaml"), nil
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg != "" {
		return filepath.Join(xdg, "tunnel", "config.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "tunnel", "config.yaml"), nil
}
