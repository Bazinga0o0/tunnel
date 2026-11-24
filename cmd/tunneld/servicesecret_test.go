package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/services"
)

// secretService writes content as the secret file of a service name in dir.
func secretService(t *testing.T, dir, name, content string) config.Service {
	t.Helper()
	path := filepath.Join(dir, name+".secret")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return config.Service{Name: name, SecretFile: path}
}

func TestReadServiceSecret(t *testing.T) {
	dir := t.TempDir()
	secret := strings.Repeat("a", minServiceSecretLength)

	got, err := readServiceSecret(secretService(t, dir, "trimmed", " \t\n"+secret+"\r\n"))
	require.NoError(t, err)
	assert.Equal(t, []byte(secret), got, "white space around the secret is not part of it")

	short := strings.Repeat("b", minServiceSecretLength-1)
	for name, content := range map[string]string{
		"short":  short + "\n",
		"padded": "    " + short + "    ",                       // white space does not count
		"runes":  strings.Repeat("ä", minServiceSecretLength-1), // characters, not bytes
		"empty":  "\n",
	} {
		_, err := readServiceSecret(secretService(t, dir, name, content))
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "at least 32 characters", name)
		assert.Contains(t, err.Error(), `"`+name+`"`, "the error names the service")
		assert.NotContains(t, err.Error(), short, "the error does not quote the secret")
	}

	_, err = readServiceSecret(config.Service{Name: "missing", SecretFile: filepath.Join(dir, "missing.secret")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"missing": secret_file`)
}

func TestServiceAPIServicesNeedTheirOwnSecrets(t *testing.T) {
	dir := t.TempDir()
	secret := strings.Repeat("c", 40)
	alpha := secretService(t, dir, "alpha", secret+"\n")
	alpha.TCPPorts = []int{19000, 19001}

	// The same secret after trimming: the API could not tell the services
	// apart.
	cfg := &config.Config{Services: []config.Service{alpha, secretService(t, dir, "beta", "  "+secret)}}
	_, err := serviceAPIServices(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"alpha" and "beta" have the same secret`)
	assert.NotContains(t, err.Error(), secret)

	// A short secret of any service ends the start.
	cfg.Services[1] = secretService(t, dir, "beta", "short")
	_, err = serviceAPIServices(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"beta"`)

	other := strings.Repeat("d", 40)
	cfg.Services[1] = secretService(t, dir, "beta", other)
	got, err := serviceAPIServices(cfg)
	require.NoError(t, err)
	assert.Equal(t, []services.APIService{
		{Name: "alpha", Secret: []byte(secret), Ports: map[int]bool{19000: true, 19001: true}},
		{Name: "beta", Secret: []byte(other), Ports: map[int]bool{}},
	}, got)
}
