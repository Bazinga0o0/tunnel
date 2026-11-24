package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
)

// ---- C4: unreadable metadata, staging certificates in production ----

// A metadata file that cannot be read (a read or permission error) stops the
// start: that is a fault for the operator to look at, not a reason to order
// a certificate.
func TestUnreadableMetadataEndsTheStart(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"a directory in its place": func(t *testing.T, dir string) {
			require.NoError(t, os.Mkdir(filepath.Join(dir, metaFile), 0o700))
		},
		"permission denied": func(t *testing.T, dir string) {
			c, k := validCert(t, 60*24*time.Hour)
			writeCacheFiles(t, dir, c, k, DirectoryProduction)
			prev := readFile
			readFile = func(name string) ([]byte, error) {
				if filepath.Base(name) == metaFile {
					return nil, fs.ErrPermission
				}
				return prev(name)
			}
			t.Cleanup(func() { readFile = prev })
		},
	}
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			cacheDir := t.TempDir()
			dir := filepath.Join(cacheDir, "production")
			require.NoError(t, os.MkdirAll(dir, 0o700))
			prepare(t, dir)
			m, created, _ := newTestManager(t, cacheDir, false, failingIssuer{t})
			err := m.start(context.Background())
			require.Error(t, err)
			assert.ErrorIs(t, err, errCacheUnreadable)
			assert.Zero(t, *created, "not a reason to order a certificate")
		})
	}
}

// A metadata file that exists but does not parse, such as the empty file a
// power loss shortly after a renewal can leave, counts as absent at
// start-up: the server warns, naming the file, and obtains a certificate.
// Before, it stopped the start for good, and systemd restarted it every five
// seconds until an operator deleted the file.
func TestCorruptMetadataCountsAsAbsentAtStart(t *testing.T) {
	for name, content := range map[string]string{
		"empty":     "",
		"garbage":   "{not json",
		"truncated": `{"domains":["tunnel.test"],"directory":"https://acme`,
	} {
		t.Run(name, func(t *testing.T) {
			cacheDir := t.TempDir()
			dir := filepath.Join(cacheDir, "production")
			c, k := validCert(t, 60*24*time.Hour)
			writeCacheFiles(t, dir, c, k, DirectoryProduction)
			require.NoError(t, os.WriteFile(filepath.Join(dir, metaFile), []byte(content), 0o600))

			iss := &fakeIssuer{t: t}
			m, _, logs := newTestManager(t, cacheDir, false, iss)
			iss.now = m.clk.Now
			require.NoError(t, m.start(context.Background()))
			assert.Equal(t, 1, iss.callCount(), "a new certificate is obtained")
			assert.Equal(t, iss.issued[0], servedSerial(t, m))
			assert.Contains(t, logs.String(), "level=WARN")
			assert.Contains(t, logs.String(), metaFile, "the warning names the file")

			raw, err := os.ReadFile(filepath.Join(dir, metaFile))
			require.NoError(t, err)
			var meta certMeta
			require.NoError(t, json.Unmarshal(raw, &meta), "the cache write replaced the file")
		})
	}
}

func TestProductionNeverServesAStagingCertificate(t *testing.T) {
	cacheDir := t.TempDir()
	certPEM, keyPEM := stagingCert(t)
	// Even with metadata that claims production.
	writeCacheFiles(t, filepath.Join(cacheDir, "production"), certPEM, keyPEM, DirectoryProduction)
	iss := &fakeIssuer{t: t}
	m, _, _ := newTestManager(t, cacheDir, false, iss)
	require.NoError(t, m.start(context.Background()))
	assert.Equal(t, 1, iss.callCount())
	assert.NotEqual(t, serialOf(t, certPEM), servedSerial(t, m))
}

// stagingIssuer returns a staging certificate.
type stagingIssuer struct{ t *testing.T }

func (s stagingIssuer) Obtain([]string) ([]byte, []byte, error) {
	c, k := stagingCert(s.t)
	return c, k, nil
}

func TestProductionRefusesAStagingCertificateFromTheCA(t *testing.T) {
	m, _, _ := newTestManager(t, t.TempDir(), false, stagingIssuer{t})
	err := m.obtain(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "staging")
	_, err = m.GetCertificate(&tls.ClientHelloInfo{})
	assert.Error(t, err, "nothing is served")
}

// ---- C5 ----

func TestRenewBeforeBoundary(t *testing.T) {
	assert.Equal(t, 30*24*time.Hour, RenewBefore)
	start := time.Now().Truncate(time.Second)
	cacheDir := t.TempDir()
	certPEM, keyPEM := genCert(t, testDomains, start.Add(-time.Hour), start.Add(RenewBefore+time.Minute))
	writeCacheFiles(t, filepath.Join(cacheDir, "production"), certPEM, keyPEM, DirectoryProduction)
	iss := &fakeIssuer{t: t}
	m, _, _ := newTestManager(t, cacheDir, false, iss)
	fc := newFakeClock(start)
	m.clk = fc
	iss.now = fc.Now
	require.NoError(t, m.start(context.Background()))

	m.checkRenewal(context.Background())
	assert.Zero(t, iss.callCount(), "one minute outside the window")
	fc.Advance(2 * time.Minute)
	m.checkRenewal(context.Background())
	assert.Equal(t, 1, iss.callCount(), "one minute inside the window")
}

// The issuer is created for the cache directory and the ACME directory of
// the config; staging and production cannot trade places unnoticed.
func TestTheIssuerGetsTheConfiguredDirectory(t *testing.T) {
	for _, staging := range []bool{false, true} {
		cacheDir := t.TempDir()
		m, _, _ := newTestManager(t, cacheDir, staging, nil)
		var gotDir, gotDirectory string
		m.newIssuer = func(dir, directory string) (Issuer, error) {
			gotDir, gotDirectory = dir, directory
			return &fakeIssuer{t: t}, nil
		}
		require.NoError(t, m.start(context.Background()))
		if staging {
			assert.Equal(t, DirectoryStaging, gotDirectory)
			assert.Equal(t, filepath.Join(cacheDir, "staging"), gotDir)
		} else {
			assert.Equal(t, DirectoryProduction, gotDirectory)
			assert.Equal(t, filepath.Join(cacheDir, "production"), gotDir)
		}
	}
	assert.Equal(t, "https://acme-v02.api.letsencrypt.org/directory", DirectoryProduction)
	assert.Equal(t, "https://acme-staging-v02.api.letsencrypt.org/directory", DirectoryStaging)

	acct, err := loadOrCreateAccount(t.TempDir(), "ops@example.com")
	require.NoError(t, err)
	cfg := legoConfig(acct, DirectoryStaging)
	assert.Equal(t, DirectoryStaging, cfg.CADirURL)
	assert.Equal(t, certcrypto.EC256, cfg.Certificate.KeyType)
	assert.Equal(t, DirectoryProduction, legoConfig(acct, DirectoryProduction).CADirURL)
}

// The local steps of the lego issuer come before the network and fail
// permanently.
func TestLegoIssuerLocalFaultsArePermanentAndOffline(t *testing.T) {
	prev := newDNSProvider
	newDNSProvider = func(string) (challenge.Provider, error) { return nil, errors.New("IONOS_API_KEY missing") }
	defer func() { newDNSProvider = prev }()

	dir := t.TempDir()
	// The directory URL cannot be reached: the provider error must come first.
	_, err := newLegoIssuer(Options{Email: "ops@example.com", DNSProvider: "ionos"}, dir, "https://127.0.0.1:1/directory")
	require.Error(t, err)
	assert.True(t, isPermanent(err))
	assert.Contains(t, err.Error(), "IONOS_API_KEY")

	require.NoError(t, os.WriteFile(filepath.Join(dir, accountFile), []byte("{broken"), 0o600))
	_, err = newLegoIssuer(Options{Email: "ops@example.com", DNSProvider: "ionos"}, dir, "https://127.0.0.1:1/directory")
	require.Error(t, err)
	assert.True(t, isPermanent(err))
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":    "example.com",
		"example.com.":   "example.com",
		"*.Example.com.": "*.example.com",
		"example.com":    "example.com",
	} {
		assert.Equal(t, want, normalizeName(in), in)
	}
}

func TestObtainExportsTheNewNotAfter(t *testing.T) {
	iss := &fakeIssuer{t: t, notAfter: 77 * 24 * time.Hour}
	m, _, _ := newTestManager(t, t.TempDir(), false, iss)
	require.NoError(t, m.obtain(context.Background()))
	cert, err := m.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, float64(leaf.NotAfter.Unix()), gaugeValue(t, metrics.CertNotAfter))
}
