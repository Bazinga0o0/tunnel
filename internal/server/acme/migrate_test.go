package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issuer names as Let's Encrypt uses them.
const (
	leProductionOrg = "Let's Encrypt"
	leProductionCN  = "R10"
	leStagingOrg    = "(STAGING) Let's Encrypt"
	leStagingCN     = "(STAGING) Pseudo Plum E5"
)

// genIssued returns a certificate signed by a generated intermediate with
// the given issuer name, as a chain (leaf first) the way lego stores it, and
// the leaf's key.
func genIssued(t *testing.T, issuerOrg, issuerCN string, dnsNames []string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{issuerOrg}, CommonName: issuerCN},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notAfter.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	require.NoError(t, err)
	leaf := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// oldAccountJSON is an account file of the previous version registered at
// host ("" writes none).
func oldAccountJSON(t *testing.T, host string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	raw, err := json.Marshal(map[string]any{
		"email":        "ops@example.com",
		"registration": map[string]any{"body": map[string]any{"status": "valid"}, "uri": "https://" + host + "/acme/acct/123"},
		"key_pem":      pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
	})
	require.NoError(t, err)
	return raw
}

// writeOldCache lays out the cache of the previous version in cacheDir.
func writeOldCache(t *testing.T, cacheDir string, certPEM, keyPEM []byte, accountHost string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, testDomains[0]+".crt"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, testDomains[0]+".key"), keyPEM, 0o600))
	if accountHost != "" {
		require.NoError(t, os.WriteFile(filepath.Join(cacheDir, accountFile), oldAccountJSON(t, accountHost), 0o600))
	}
}

// failingIssuer fails the test when it is asked for a certificate. Its error
// is permanent, so that a start that reaches it ends instead of waiting on a
// fake clock nobody advances.
type failingIssuer struct{ t *testing.T }

func (f failingIssuer) Obtain([]string) ([]byte, []byte, error) {
	f.t.Error("the CA was contacted")
	return nil, nil, permanent(errors.New("no CA in this test"))
}

func prodCert(t *testing.T) ([]byte, []byte) {
	return genIssued(t, leProductionOrg, leProductionCN, testDomains, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
}

func stagingCert(t *testing.T) ([]byte, []byte) {
	return genIssued(t, leStagingOrg, leStagingCN, testDomains, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
}

func TestOldProductionCacheIsMigrated(t *testing.T) {
	cacheDir := t.TempDir()
	certPEM, keyPEM := prodCert(t)
	writeOldCache(t, cacheDir, certPEM, keyPEM, productionHost)
	oldAccount, err := os.ReadFile(filepath.Join(cacheDir, accountFile))
	require.NoError(t, err)

	m, created, log := newTestManager(t, cacheDir, false, failingIssuer{t})
	require.NoError(t, m.start(context.Background()))
	assert.Zero(t, *created, "no ACME client")
	assert.Equal(t, serialOf(t, certPEM), servedSerial(t, m))
	assert.Equal(t, 1, strings.Count(log.String(), "migrated the certificate cache"), log.String())

	dir := filepath.Join(cacheDir, "production")
	got, err := os.ReadFile(filepath.Join(dir, certFile))
	require.NoError(t, err)
	assert.Equal(t, certPEM, got)
	gotAccount, err := os.ReadFile(filepath.Join(dir, accountFile))
	require.NoError(t, err)
	assert.Equal(t, oldAccount, gotAccount, "the account is copied: renewals keep it")
	raw, err := os.ReadFile(filepath.Join(dir, metaFile))
	require.NoError(t, err)
	var meta certMeta
	require.NoError(t, json.Unmarshal(raw, &meta))
	assert.Equal(t, DirectoryProduction, meta.Directory)
	assert.Equal(t, filepath.Join(cacheDir, testDomains[0]+".crt"), meta.MigratedFrom)

	// The old files stay for the operator to remove.
	for _, name := range []string{testDomains[0] + ".crt", testDomains[0] + ".key", accountFile} {
		assert.FileExists(t, filepath.Join(cacheDir, name))
	}
}

func TestOldCacheWithoutAccountIsMigratedByItsIssuer(t *testing.T) {
	cacheDir := t.TempDir()
	certPEM, keyPEM := prodCert(t)
	writeOldCache(t, cacheDir, certPEM, keyPEM, "")

	m, created, _ := newTestManager(t, cacheDir, false, failingIssuer{t})
	require.NoError(t, m.start(context.Background()))
	assert.Zero(t, *created)
	assert.Equal(t, serialOf(t, certPEM), servedSerial(t, m))
	assert.NoFileExists(t, filepath.Join(cacheDir, "production", accountFile))
}

func TestOldStagingCacheGoesOnlyToStaging(t *testing.T) {
	certPEM, keyPEM := stagingCert(t)

	// Production does not take it ...
	cacheDir := t.TempDir()
	writeOldCache(t, cacheDir, certPEM, keyPEM, stagingHost)
	iss := &fakeIssuer{t: t}
	prod, _, log := newTestManager(t, cacheDir, false, iss)
	require.NoError(t, prod.start(context.Background()))
	assert.Equal(t, 1, iss.callCount(), "a production certificate is obtained")
	assert.NotEqual(t, serialOf(t, certPEM), servedSerial(t, prod))
	assert.Contains(t, log.String(), "not migrated")
	assert.NotContains(t, log.String(), "migrated the certificate cache")

	// ... staging does.
	cacheDir = t.TempDir()
	writeOldCache(t, cacheDir, certPEM, keyPEM, stagingHost)
	staging, created, _ := newTestManager(t, cacheDir, true, failingIssuer{t})
	require.NoError(t, staging.start(context.Background()))
	assert.Zero(t, *created)
	assert.Equal(t, serialOf(t, certPEM), servedSerial(t, staging))

	// And a production cache does not go into staging.
	cacheDir = t.TempDir()
	prodPEM, prodKey := prodCert(t)
	writeOldCache(t, cacheDir, prodPEM, prodKey, productionHost)
	iss = &fakeIssuer{t: t}
	staging, _, log = newTestManager(t, cacheDir, true, iss)
	require.NoError(t, staging.start(context.Background()))
	assert.Equal(t, 1, iss.callCount())
	assert.NotContains(t, log.String(), "migrated the certificate cache")
}

func TestOldCacheInDoubtIsNotMigrated(t *testing.T) {
	now := time.Now()
	cases := map[string]struct {
		staging bool
		prepare func(t *testing.T, dir string)
	}{
		"expired": {false, func(t *testing.T, dir string) {
			c, k := genIssued(t, leProductionOrg, leProductionCN, testDomains, now.Add(-90*24*time.Hour), now.Add(-time.Minute))
			writeOldCache(t, dir, c, k, productionHost)
		}},
		"wrong names": {false, func(t *testing.T, dir string) {
			c, k := genIssued(t, leProductionOrg, leProductionCN, []string{"example.org", "*.example.org"}, now.Add(-time.Hour), now.Add(60*24*time.Hour))
			writeOldCache(t, dir, c, k, productionHost)
		}},
		"wildcard missing": {false, func(t *testing.T, dir string) {
			c, k := genIssued(t, leProductionOrg, leProductionCN, []string{"example.com"}, now.Add(-time.Hour), now.Add(60*24*time.Hour))
			writeOldCache(t, dir, c, k, productionHost)
		}},
		"key of another certificate": {false, func(t *testing.T, dir string) {
			c, _ := prodCert(t)
			_, k := prodCert(t)
			writeOldCache(t, dir, c, k, productionHost)
		}},
		"unknown issuer, no account": {false, func(t *testing.T, dir string) {
			c, k := genIssued(t, "Some Other CA", "Other R1", testDomains, now.Add(-time.Hour), now.Add(60*24*time.Hour))
			writeOldCache(t, dir, c, k, "")
		}},
		"account of an unknown CA": {false, func(t *testing.T, dir string) {
			c, k := genIssued(t, "Some Other CA", "Other R1", testDomains, now.Add(-time.Hour), now.Add(60*24*time.Hour))
			writeOldCache(t, dir, c, k, "acme.other-ca.example")
		}},
		"account of an unknown CA, Let's Encrypt certificate": {false, func(t *testing.T, dir string) {
			c, k := prodCert(t)
			writeOldCache(t, dir, c, k, "acme.other-ca.example")
		}},
		"garbled account file": {false, func(t *testing.T, dir string) {
			c, k := prodCert(t)
			writeOldCache(t, dir, c, k, "")
			require.NoError(t, os.WriteFile(filepath.Join(dir, accountFile), []byte("{not json"), 0o600))
		}},
		"account file without registration": {false, func(t *testing.T, dir string) {
			c, k := prodCert(t)
			writeOldCache(t, dir, c, k, "")
			require.NoError(t, os.WriteFile(filepath.Join(dir, accountFile), []byte(`{"email":"ops@example.com"}`), 0o600))
		}},
		"account with a corrupt key": {false, func(t *testing.T, dir string) {
			c, k := prodCert(t)
			writeOldCache(t, dir, c, k, "")
			raw := `{"email":"ops@example.com","registration":{"body":{},"uri":"https://` + productionHost +
				`/acme/acct/1"},"key_pem":"` + base64.StdEncoding.EncodeToString([]byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")) + `"}`
			require.NoError(t, os.WriteFile(filepath.Join(dir, accountFile), []byte(raw), 0o600))
		}},
		"unreadable account file": {false, func(t *testing.T, dir string) {
			c, k := prodCert(t)
			writeOldCache(t, dir, c, k, "")
			require.NoError(t, os.Mkdir(filepath.Join(dir, accountFile), 0o700))
		}},
		"production account, issuer not Let's Encrypt": {false, func(t *testing.T, dir string) {
			c, k := genIssued(t, "Some Other CA", "Other R1", testDomains, now.Add(-time.Hour), now.Add(60*24*time.Hour))
			writeOldCache(t, dir, c, k, productionHost)
		}},
		"production account, staging certificate": {true, func(t *testing.T, dir string) {
			c, k := stagingCert(t)
			writeOldCache(t, dir, c, k, productionHost)
		}},
		"staging account, production certificate": {false, func(t *testing.T, dir string) {
			c, k := prodCert(t)
			writeOldCache(t, dir, c, k, stagingHost)
		}},
		// The account names the configured directory, the issuer the other
		// one: only the disagreement rule stops this.
		"staging account, production certificate, staging configured": {true, func(t *testing.T, dir string) {
			c, k := prodCert(t)
			writeOldCache(t, dir, c, k, stagingHost)
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cacheDir := t.TempDir()
			tc.prepare(t, cacheDir)
			iss := &fakeIssuer{t: t}
			m, _, log := newTestManager(t, cacheDir, tc.staging, iss)
			require.NoError(t, m.start(context.Background()))
			assert.Equal(t, 1, iss.callCount(), "obtained as without the old files")
			assert.Contains(t, log.String(), "not migrated")
			assert.NotContains(t, log.String(), "migrated the certificate cache")
		})
	}
}

// A migration that died between writing the certificate and its metadata
// (the metadata is written last) left no certificate set: it is done again.
func TestInterruptedMigrationIsDoneAgain(t *testing.T) {
	cacheDir := t.TempDir()
	certPEM, keyPEM := prodCert(t)
	writeOldCache(t, cacheDir, certPEM, keyPEM, productionHost)
	dir := filepath.Join(cacheDir, "production")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, certFile), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, keyFile), keyPEM, 0o600))

	m, created, log := newTestManager(t, cacheDir, false, failingIssuer{t})
	require.NoError(t, m.start(context.Background()))
	assert.Zero(t, *created)
	assert.Equal(t, serialOf(t, certPEM), servedSerial(t, m))
	assert.Contains(t, log.String(), "migrated the certificate cache")
}

func TestMigrationHappensOnce(t *testing.T) {
	cacheDir := t.TempDir()
	first, firstKey := prodCert(t)
	writeOldCache(t, cacheDir, first, firstKey, productionHost)
	m, _, _ := newTestManager(t, cacheDir, false, failingIssuer{t})
	require.NoError(t, m.start(context.Background()))

	// Another valid certificate in the old place is not taken again.
	second, secondKey := prodCert(t)
	writeOldCache(t, cacheDir, second, secondKey, productionHost)
	again, created, log := newTestManager(t, cacheDir, false, failingIssuer{t})
	require.NoError(t, again.start(context.Background()))
	assert.Zero(t, *created)
	assert.Equal(t, serialOf(t, first), servedSerial(t, again))
	assert.NotContains(t, log.String(), "migrated")
}
