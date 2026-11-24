package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/acme"
	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
)

func gauge(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, g.Write(&m))
	return m.GetGauge().GetValue()
}

func notAfterOf(t *testing.T, certPEM []byte) time.Time {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	c, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return c.NotAfter
}

func TestTLSSourceSelfSignedIsLogged(t *testing.T) {
	logger, logs := captureLog()
	cfg := &config.Config{TLS: config.TLS{SelfSignedHosts: []string{"tunnel.test"}}}
	tlsCfg, mgr, err := buildTLSConfig(context.Background(), cfg, logger)
	require.NoError(t, err)
	assert.Nil(t, mgr)
	require.Len(t, tlsCfg.Certificates, 1)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion)
	assert.Contains(t, logs.String(), "tls source: self-signed")
}

func TestTLSSourceCertificateFilesIsLoggedAndExported(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"tunnel.test"})
	require.NoError(t, err)
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	logger, logs := captureLog()
	cfg := &config.Config{TLS: config.TLS{CertFile: certPath, KeyFile: keyPath}}
	tlsCfg, mgr, err := buildTLSConfig(context.Background(), cfg, logger)
	require.NoError(t, err)
	assert.Nil(t, mgr)
	require.Len(t, tlsCfg.Certificates, 1)
	assert.Contains(t, logs.String(), "tls source: certificate files")
	assert.Equal(t, float64(notAfterOf(t, certPEM).Unix()), gauge(t, metrics.CertNotAfter))
}

// issuerFunc adapts a function to acme.Issuer.
type issuerFunc func(domains []string) ([]byte, []byte, error)

func (f issuerFunc) Obtain(domains []string) ([]byte, []byte, error) { return f(domains) }

// With a valid cache the server gets its certificate without the ACME
// directory and without the DNS provider.
func TestTLSSourceACMEStartsFromAValidCacheWithoutTheNetwork(t *testing.T) {
	// No real CA can be reached from this test: the issuer is injected, so
	// buildTLSConfig never builds the lego client, and the DNS provider's
	// key is cleared as a second guard. Should the cache ever be refused,
	// the injected issuer fails the test and ends the start through the
	// context instead of letting the backoff wait.
	t.Setenv("IONOS_API_KEY", "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	prev := acmeIssuer
	acmeIssuer = issuerFunc(func([]string) ([]byte, []byte, error) {
		t.Error("the CA was contacted")
		cancel()
		return nil, nil, errors.New("no CA in this test")
	})
	defer func() { acmeIssuer = prev }()
	cacheDir := t.TempDir()
	domains := []string{"tunnel.test", "*.tunnel.test"}
	certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert(domains)
	require.NoError(t, err)
	dir := filepath.Join(cacheDir, "production")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "certificate.pem"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "private-key.pem"), keyPEM, 0o600))
	meta, err := json.Marshal(map[string]any{"directory": acme.DirectoryProduction, "domains": domains})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "certificate.json"), meta, 0o600))

	logger, logs := captureLog()
	cfg := &config.Config{TLS: config.TLS{ACME: &config.ACME{
		Email: "ops@tunnel.test", DNSProvider: "ionos", Domains: domains, CacheDir: cacheDir,
	}}}
	tlsCfg, mgr, err := buildTLSConfig(ctx, cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	cert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Contains(t, logs.String(), "tls source: acme")
	assert.NoFileExists(t, filepath.Join(dir, "account.json"), "no ACME account was needed")
}
