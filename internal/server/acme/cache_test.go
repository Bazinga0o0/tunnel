package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
)

// No test here talks to an ACME directory or a DNS provider: certificates are
// generated locally and the issuer is a fake.

var testDomains = []string{"example.com", "*.example.com"}

// genCert returns a self-signed certificate and its key in PEM.
func genCert(t *testing.T, dnsNames []string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func validCert(t *testing.T, notAfterIn time.Duration) (certPEM, keyPEM []byte) {
	t.Helper()
	return genCert(t, testDomains, time.Now().Add(-time.Hour), time.Now().Add(notAfterIn))
}

// serialOf returns the serial number of a PEM certificate.
func serialOf(t *testing.T, certPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	c, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return c.SerialNumber.String()
}

// servedSerial returns the serial number of the certificate the manager hands
// out.
func servedSerial(t *testing.T, m *Manager) string {
	t.Helper()
	cert, err := m.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	c, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	return c.SerialNumber.String()
}

// writeCacheFiles puts a certificate into a cache directory the way obtain
// does, with the metadata naming the directory URL.
func writeCacheFiles(t *testing.T, dir string, certPEM, keyPEM []byte, directoryURL string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, certFile), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, keyFile), keyPEM, 0o600))
	meta, err := json.Marshal(certMeta{Directory: directoryURL, Domains: testDomains})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, metaFile), meta, 0o600))
}

// fakeIssuer hands out certificates generated on the spot.
type fakeIssuer struct {
	t        *testing.T
	mu       sync.Mutex
	calls    int
	err      error
	notAfter time.Duration
	issued   []string         // serials
	now      func() time.Time // the clock of the certificates; nil: time.Now
}

func (f *fakeIssuer) Obtain(domains []string) ([]byte, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, nil, f.err
	}
	notAfter := f.notAfter
	if notAfter == 0 {
		notAfter = 90 * 24 * time.Hour
	}
	now := time.Now()
	if f.now != nil {
		now = f.now()
	}
	certPEM, keyPEM := genCert(f.t, domains, now.Add(-time.Minute), now.Add(notAfter))
	f.issued = append(f.issued, serialOf(f.t, certPEM))
	return certPEM, keyPEM, nil
}

func (f *fakeIssuer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// testLog is a goroutine-safe log sink.
type testLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *testLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *testLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// newTestManager prepares a manager whose issuer is iss; it counts how often
// the issuer is created. Nothing is loaded or obtained yet.
func newTestManager(t *testing.T, cacheDir string, staging bool, iss Issuer) (*Manager, *int, *testLog) {
	t.Helper()
	log := &testLog{}
	m, err := newManager(Options{
		Email:       "ops@example.com",
		Domains:     testDomains,
		CacheDir:    cacheDir,
		DNSProvider: "ionos",
		Staging:     staging,
		Logger:      slog.New(slog.NewTextHandler(log, nil)),
	})
	require.NoError(t, err)
	created := 0
	m.clk = newFakeClock(time.Now())
	m.newIssuer = func(string, string) (Issuer, error) {
		created++
		return iss, nil
	}
	return m, &created, log
}

func TestValidCacheIsUsedWithoutContactingTheCA(t *testing.T) {
	cacheDir := t.TempDir()
	certPEM, keyPEM := validCert(t, 60*24*time.Hour)
	writeCacheFiles(t, filepath.Join(cacheDir, "production"), certPEM, keyPEM, DirectoryProduction)

	m, created, _ := newTestManager(t, cacheDir, false, &fakeIssuer{t: t})
	require.NoError(t, m.start(context.Background()))
	assert.Zero(t, *created, "no ACME client is created while the cache is valid")
	assert.Equal(t, serialOf(t, certPEM), servedSerial(t, m))

	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, float64(leaf.NotAfter.Unix()), gaugeValue(t, metrics.CertNotAfter),
		"the certificate's NotAfter is exported")
}

func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, g.Write(&m))
	return m.GetGauge().GetValue()
}

func TestUnusableCacheIsReplaced(t *testing.T) {
	now := time.Now()
	cases := map[string]func(t *testing.T, dir string){
		"nothing cached": func(t *testing.T, dir string) {},
		"expired": func(t *testing.T, dir string) {
			c, k := genCert(t, testDomains, now.Add(-90*24*time.Hour), now.Add(-time.Minute))
			writeCacheFiles(t, dir, c, k, DirectoryProduction)
		},
		"not valid yet": func(t *testing.T, dir string) {
			c, k := genCert(t, testDomains, now.Add(time.Hour), now.Add(90*24*time.Hour))
			writeCacheFiles(t, dir, c, k, DirectoryProduction)
		},
		"wildcard missing": func(t *testing.T, dir string) {
			c, k := genCert(t, []string{"example.com"}, now.Add(-time.Hour), now.Add(60*24*time.Hour))
			writeCacheFiles(t, dir, c, k, DirectoryProduction)
		},
		"other domains": func(t *testing.T, dir string) {
			c, k := genCert(t, []string{"example.org", "*.example.org"}, now.Add(-time.Hour), now.Add(60*24*time.Hour))
			writeCacheFiles(t, dir, c, k, DirectoryProduction)
		},
		"issued by another directory": func(t *testing.T, dir string) {
			c, k := validCert(t, 60*24*time.Hour)
			writeCacheFiles(t, dir, c, k, DirectoryStaging)
		},
		"no metadata": func(t *testing.T, dir string) {
			c, k := validCert(t, 60*24*time.Hour)
			writeCacheFiles(t, dir, c, k, DirectoryProduction)
			require.NoError(t, os.Remove(filepath.Join(dir, metaFile)))
		},
		"certificate does not parse": func(t *testing.T, dir string) {
			c, k := validCert(t, 60*24*time.Hour)
			writeCacheFiles(t, dir, c, k, DirectoryProduction)
			require.NoError(t, os.WriteFile(filepath.Join(dir, certFile), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o600))
		},
		"key of another certificate": func(t *testing.T, dir string) {
			c, _ := validCert(t, 60*24*time.Hour)
			_, otherKey := validCert(t, 60*24*time.Hour)
			writeCacheFiles(t, dir, c, otherKey, DirectoryProduction)
		},
	}
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			cacheDir := t.TempDir()
			dir := filepath.Join(cacheDir, "production")
			prepare(t, dir)

			iss := &fakeIssuer{t: t}
			m, created, log := newTestManager(t, cacheDir, false, iss)
			require.NoError(t, m.start(context.Background()))
			assert.Equal(t, 1, *created)
			require.Equal(t, 1, iss.callCount(), "a new certificate is obtained")
			assert.Equal(t, iss.issued[0], servedSerial(t, m))
			assert.Contains(t, log.String(), "requesting a new one")

			// The new certificate replaced the cache and is used from it
			// at the next start, without the CA.
			again, createdAgain, _ := newTestManager(t, cacheDir, false, &fakeIssuer{t: t})
			require.NoError(t, again.start(context.Background()))
			assert.Zero(t, *createdAgain)
			assert.Equal(t, iss.issued[0], servedSerial(t, again))
		})
	}
}

func TestStagingAndProductionKeepSeparateCaches(t *testing.T) {
	cacheDir := t.TempDir()
	stagingCert, stagingKey := validCert(t, 60*24*time.Hour)
	writeCacheFiles(t, filepath.Join(cacheDir, "staging"), stagingCert, stagingKey, DirectoryStaging)

	// Production does not take the staging certificate.
	iss := &fakeIssuer{t: t}
	prod, _, _ := newTestManager(t, cacheDir, false, iss)
	require.NoError(t, prod.start(context.Background()))
	require.Equal(t, 1, iss.callCount())
	assert.NotEqual(t, serialOf(t, stagingCert), servedSerial(t, prod))
	assert.FileExists(t, filepath.Join(cacheDir, "production", certFile))

	// The staging cache is untouched and still used for staging.
	got, err := os.ReadFile(filepath.Join(cacheDir, "staging", certFile))
	require.NoError(t, err)
	assert.Equal(t, stagingCert, got)
	staging, created, log := newTestManager(t, cacheDir, true, &fakeIssuer{t: t})
	require.NoError(t, staging.start(context.Background()))
	assert.Zero(t, *created)
	assert.Equal(t, serialOf(t, stagingCert), servedSerial(t, staging))
	assert.Contains(t, log.String(), "level=WARN")
	assert.Contains(t, log.String(), "staging")
}

func TestObtainedCertificateIsCachedPrivately(t *testing.T) {
	cacheDir := t.TempDir()
	m, _, _ := newTestManager(t, cacheDir, false, &fakeIssuer{t: t})
	require.NoError(t, m.start(context.Background()))

	dir := filepath.Join(cacheDir, "production")
	for _, name := range []string{certFile, keyFile, metaFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err, name)
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), name)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, metaFile))
	require.NoError(t, err)
	var meta certMeta
	require.NoError(t, json.Unmarshal(raw, &meta))
	assert.Equal(t, DirectoryProduction, meta.Directory)
	assert.Equal(t, testDomains, meta.Domains)
}

// Problems that waiting does not cure end the start; nothing is retried.
func TestPermanentErrorsEndTheStart(t *testing.T) {
	broken, _, _ := newTestManager(t, t.TempDir(), false, nil)
	calls := 0
	broken.newIssuer = func(string, string) (Issuer, error) {
		calls++
		return nil, permanent(errors.New("account file unreadable"))
	}
	err := broken.start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "account file unreadable")
	assert.Equal(t, 1, calls)
	_, err = broken.GetCertificate(&tls.ClientHelloInfo{})
	assert.Error(t, err)
	assert.NoFileExists(t, filepath.Join(broken.dir, backoffFile), "no backoff for a local fault")
}

func TestTheACMEClientIsCreatedOnce(t *testing.T) {
	iss := &fakeIssuer{t: t}
	m, created, _ := newTestManager(t, t.TempDir(), false, iss)
	require.NoError(t, m.start(context.Background()))
	require.NoError(t, m.obtain(context.Background()))
	assert.Equal(t, 1, *created)
	assert.Equal(t, 2, iss.callCount())
}

func TestRenewalIsCheckedAtStartAndThenEveryInterval(t *testing.T) {
	assert.Equal(t, 12*time.Hour, RenewalCheckInterval)

	cacheDir := t.TempDir()
	certPEM, keyPEM := validCert(t, 10*24*time.Hour) // inside the renewal window
	writeCacheFiles(t, filepath.Join(cacheDir, "production"), certPEM, keyPEM, DirectoryProduction)

	iss := &fakeIssuer{t: t}
	m, created, _ := newTestManager(t, cacheDir, false, iss)
	fc := m.clk.(*fakeClock)
	iss.now = fc.Now
	require.NoError(t, m.start(context.Background()))
	require.Zero(t, *created, "the server starts on the cached certificate")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.RenewalLoop(ctx)
	}()

	// The first check runs before the loop waits for the first time.
	d := fc.nextWait(t)
	assert.Equal(t, 1, iss.callCount(), "renewed at once")
	assert.Equal(t, iss.issued[0], servedSerial(t, m))
	assert.Equal(t, 12*time.Hour, d, "the new certificate has 90 days: the next check in 12 hours")

	// The checks after that leave the new certificate alone ...
	fc.Advance(d)
	assert.Equal(t, 12*time.Hour, fc.nextWait(t))
	assert.Equal(t, 1, iss.callCount())

	// ... until it reaches its renewal window.
	fc.Advance(70 * 24 * time.Hour)
	fc.nextWait(t)
	assert.Equal(t, 2, iss.callCount())

	cancel()
	fc.Advance(24 * time.Hour)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RenewalLoop did not return after the context ended")
	}
}

func TestFailedRenewalKeepsTheCurrentCertificate(t *testing.T) {
	cacheDir := t.TempDir()
	certPEM, keyPEM := validCert(t, 5*24*time.Hour)
	writeCacheFiles(t, filepath.Join(cacheDir, "production"), certPEM, keyPEM, DirectoryProduction)
	iss := &fakeIssuer{t: t, err: errors.New("dns provider down")}
	m, _, log := newTestManager(t, cacheDir, false, iss)
	require.NoError(t, m.start(context.Background()))

	m.checkRenewal(context.Background())
	assert.Equal(t, 1, iss.callCount())
	assert.Equal(t, serialOf(t, certPEM), servedSerial(t, m))
	assert.Contains(t, log.String(), "renewal failed")
}

func TestAccountIsCreatedOnlyWhenTheFileDoesNotExist(t *testing.T) {
	dir := t.TempDir()
	acct, err := loadOrCreateAccount(dir, "ops@example.com")
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(dir, accountFile))

	again, err := loadOrCreateAccount(dir, "ops@example.com")
	require.NoError(t, err)
	assert.Equal(t, acct.KeyPEM, again.KeyPEM, "an existing account is loaded, not replaced")

	// Any other read error is fatal and leaves the file alone.
	unreadable := t.TempDir()
	original := []byte(`{"email":"ops@example.com"}`)
	require.NoError(t, os.WriteFile(filepath.Join(unreadable, accountFile), original, 0o600))
	prevRead := readFile
	readFile = func(string) ([]byte, error) { return nil, fs.ErrPermission }
	_, err = loadOrCreateAccount(unreadable, "ops@example.com")
	readFile = prevRead
	require.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrPermission)
	raw, readErr := os.ReadFile(filepath.Join(unreadable, accountFile))
	require.NoError(t, readErr)
	assert.Equal(t, original, raw, "no new account was written in its place")

	// A directory in place of the file is another read error.
	isDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(isDir, accountFile), 0o700))
	_, err = loadOrCreateAccount(isDir, "ops@example.com")
	require.Error(t, err)

	corrupt := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(corrupt, accountFile), []byte("{not json"), 0o600))
	_, err = loadOrCreateAccount(corrupt, "ops@example.com")
	require.Error(t, err)
	raw, readErr = os.ReadFile(filepath.Join(corrupt, accountFile))
	require.NoError(t, readErr)
	assert.Equal(t, "{not json", string(raw))
}

func TestNewRefusesAnUnsupportedProviderBeforeAnyNetwork(t *testing.T) {
	_, err := newManager(Options{Email: "ops@example.com", Domains: testDomains, CacheDir: t.TempDir(), DNSProvider: "route53"})
	require.Error(t, err)
	_, err = newManager(Options{Email: "ops@example.com", CacheDir: t.TempDir(), DNSProvider: "ionos"})
	require.Error(t, err)
	_, err = newManager(Options{Domains: testDomains, CacheDir: t.TempDir(), DNSProvider: "ionos"})
	require.Error(t, err)
}
