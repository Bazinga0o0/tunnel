package acme

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Files in a cache directory.
const (
	accountFile = "account.json"
	certFile    = "certificate.pem" // leaf and chain
	keyFile     = "private-key.pem"
	metaFile    = "certificate.json"    // certMeta; written last
	backoffFile = "obtain-backoff.json" // backoffState; from an attempt until its certificate is cached
)

// errCacheUnreadable marks a cache file that exists but cannot be read (a
// read or permission error). That is a fault to look at, not a reason to
// order a certificate.
var errCacheUnreadable = errors.New("cache file unreadable")

// errCacheCorrupt marks a metadata file that can be read but does not parse,
// such as the empty or partial file a power loss right after a cache write
// can leave behind. It counts as no cached certificate.
var errCacheCorrupt = errors.New("cache file does not parse")

// readFile and createTemp are os.ReadFile and os.CreateTemp; tests replace
// them to simulate errors the file system of the test machine cannot
// produce.
var (
	readFile   = os.ReadFile
	createTemp = os.CreateTemp
)

// certMeta records where a cached certificate came from.
type certMeta struct {
	Directory    string    `json:"directory"`
	Domains      []string  `json:"domains"`
	ObtainedAt   time.Time `json:"obtained_at"`
	MigratedFrom string    `json:"migrated_from,omitempty"` // the file of the previous version's cache
}

// hasCertSet reports whether dir holds a certificate set, usable or not. The
// metadata file decides: it is written last, so a certificate without it is
// the rest of a write that did not finish.
func hasCertSet(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, metaFile))
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

// loadCachedCert returns the cached certificate if it can be used: metadata,
// certificate and key parse and belong together, it was issued by
// directory, and checkCert accepts it. A metadata file that exists but
// cannot be read is an error wrapping errCacheUnreadable, one that does not
// parse an error wrapping errCacheCorrupt; every other reason makes the
// certificate unusable, which the caller answers by obtaining a new one.
func loadCachedCert(dir string, domains []string, directory string, now time.Time) (*tls.Certificate, time.Time, error) {
	raw, err := readFile(filepath.Join(dir, metaFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, time.Time{}, errors.New("no cached certificate")
		}
		return nil, time.Time{}, fmt.Errorf("%w: read %s: %w", errCacheUnreadable, filepath.Join(dir, metaFile), err)
	}
	var meta certMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, time.Time{}, fmt.Errorf("%w: %s: %w", errCacheCorrupt, filepath.Join(dir, metaFile), err)
	}
	if meta.Directory != directory {
		return nil, time.Time{}, fmt.Errorf("the cached certificate was issued by %q, not by %q", meta.Directory, directory)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, certFile), filepath.Join(dir, keyFile))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("load cached certificate: %w", err)
	}
	leaf, err := checkCert(&cert, domains, directory, now)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("the cached certificate %w", err)
	}
	return &cert, leaf.NotAfter, nil
}

// checkCert applies the rules every certificate the manager serves from disk
// must meet: valid at now, every one of domains among its names, and not a
// staging certificate when the production directory is configured. The
// error reads as a predicate ("expired at ...").
func checkCert(cert *tls.Certificate, domains []string, directory string, now time.Time) (*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("does not parse: %w", err)
	}
	switch {
	case !now.Before(leaf.NotAfter):
		return nil, fmt.Errorf("expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	case now.Before(leaf.NotBefore):
		return nil, fmt.Errorf("is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	case !covers(leaf, domains):
		return nil, fmt.Errorf("does not cover all of %v", domains)
	case directory == DirectoryProduction && isStagingIssuer(leaf):
		return nil, errors.New("comes from the Let's Encrypt staging CA, but production is configured")
	}
	return leaf, nil
}

// isStagingIssuer reports whether the certificate was issued by a Let's
// Encrypt staging intermediate; their names carry "(STAGING)".
func isStagingIssuer(leaf *x509.Certificate) bool {
	if strings.Contains(leaf.Issuer.CommonName, "(STAGING)") {
		return true
	}
	for _, o := range leaf.Issuer.Organization {
		if strings.Contains(o, "(STAGING)") {
			return true
		}
	}
	return false
}

// isLetsEncryptIssuer reports whether the certificate names Let's Encrypt as
// the organisation of its issuer.
func isLetsEncryptIssuer(leaf *x509.Certificate) bool {
	for _, o := range leaf.Issuer.Organization {
		if strings.Contains(o, "Let's Encrypt") {
			return true
		}
	}
	return false
}

// covers reports whether the certificate names every domain, compared
// without regard to case and a trailing dot.
func covers(leaf *x509.Certificate, domains []string) bool {
	names := make(map[string]bool, len(leaf.DNSNames))
	for _, n := range leaf.DNSNames {
		names[normalizeName(n)] = true
	}
	for _, d := range domains {
		if !names[normalizeName(d)] {
			return false
		}
	}
	return true
}

func normalizeName(n string) string {
	return strings.TrimSuffix(strings.ToLower(n), ".")
}

// writeCache stores certificate, key and metadata, each through a temporary
// file that is renamed into place. The metadata goes last: until it names the
// directory the set is not used.
func writeCache(dir string, certPEM, keyPEM []byte, meta certMeta) error {
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, metaFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{keyFile, keyPEM}, {certFile, certPEM}, {metaFile, metaJSON}} {
		if err := writeFileAtomic(filepath.Join(dir, f.name), f.data); err != nil {
			return err
		}
	}
	return nil
}

// writeFileAtomic writes data to path with mode 0600 through a temporary
// file in the same directory.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := createTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// probeWritable creates and removes a file in dir.
func probeWritable(dir string) error {
	tmp, err := createTemp(dir, ".probe.*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Remove(name)
}
