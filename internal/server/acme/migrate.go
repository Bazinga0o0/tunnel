package acme

import (
	"crypto/tls"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Hosts of the two Let's Encrypt directories, as they appear in the
// registration URI of an account.
const (
	productionHost = "acme-v02.api.letsencrypt.org"
	stagingHost    = "acme-staging-v02.api.letsencrypt.org"
)

// migrateOldCache copies the cache of the previous version into the
// directory of the configured ACME directory, once: the previous version
// kept <cache_dir>/<first domain>.crt and .key and <cache_dir>/account.json,
// with production and staging in one place. It is called only when the new
// location has no certificate set.
//
// The certificate is taken only if it passes the checks of every cached
// certificate and belongs to the configured directory, judged by the
// account's registration URI when the account file can be read and by the
// certificate's issuer otherwise; in any doubt nothing is migrated and the
// manager obtains a certificate as it would without the old files. The old
// files are copied, never moved or deleted.
func (m *Manager) migrateOldCache() {
	oldCert := filepath.Join(m.opts.CacheDir, m.opts.Domains[0]+".crt")
	oldKey := filepath.Join(m.opts.CacheDir, m.opts.Domains[0]+".key")
	if _, err := os.Stat(oldCert); err != nil {
		return // nothing from the previous version
	}
	skip := func(reason string) {
		m.logger.Info("acme: the certificate of the previous version is not migrated", "file", oldCert, "reason", reason)
	}

	certPEM, err := readFile(oldCert)
	if err != nil {
		skip(err.Error())
		return
	}
	keyPEM, err := readFile(oldKey)
	if err != nil {
		skip(err.Error())
		return
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		skip("certificate and key do not parse together: " + err.Error())
		return
	}
	leaf, err := checkCert(&cert, m.opts.Domains, m.directory, m.clk.Now())
	if err != nil {
		skip("the certificate " + err.Error())
		return
	}

	oldAccount := filepath.Join(m.opts.CacheDir, accountFile)
	accountRaw, accountDir, accountExists := readOldAccount(oldAccount)
	var directory string
	switch {
	case accountExists && accountDir == "":
		skip("the old account file cannot be read or names no Let's Encrypt directory")
		return
	case accountDir != "":
		directory = accountDir
	case isStagingIssuer(leaf):
		directory = DirectoryStaging
	case isLetsEncryptIssuer(leaf):
		directory = DirectoryProduction
	default:
		skip("neither the account nor the issuer says which ACME directory issued it")
		return
	}
	if (directory == DirectoryProduction) == isStagingIssuer(leaf) {
		skip("the account and the issuer disagree about the ACME directory")
		return
	}
	if directory == DirectoryProduction && !isLetsEncryptIssuer(leaf) {
		skip("the issuer is not Let's Encrypt")
		return
	}
	if directory != m.directory {
		skip("it was issued by " + directory + ", the config names " + m.directory)
		return
	}

	// The account goes first: a certificate without its account would make
	// the next renewal register a new one.
	if accountRaw != nil {
		if _, err := os.Stat(filepath.Join(m.dir, accountFile)); errors.Is(err, os.ErrNotExist) {
			if err := writeFileAtomic(filepath.Join(m.dir, accountFile), accountRaw); err != nil {
				skip("copying the account failed: " + err.Error())
				return
			}
		}
	}
	meta := certMeta{Directory: m.directory, Domains: m.opts.Domains, ObtainedAt: time.Time{}, MigratedFrom: oldCert}
	if err := writeCache(m.dir, certPEM, keyPEM, meta); err != nil {
		skip("writing the new cache failed: " + err.Error())
		return
	}
	m.logger.Info("acme: migrated the certificate cache of the previous version; the old files can be removed",
		"from", oldCert, "to", m.dir, "account", accountRaw != nil, "not_after", leaf.NotAfter)
}

// readOldAccount reads the previous version's account file and returns its
// content and the ACME directory its registration URI names, or nil and ""
// when it cannot be read or names no known directory. exists reports whether
// there is a file at all.
func readOldAccount(path string) (raw []byte, directory string, exists bool) {
	raw, err := readFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", false
	}
	if err != nil {
		return nil, "", true
	}
	// Parsed like an account in use, key included: an account whose key
	// does not parse would stop the first renewal for good.
	acct, err := parseAccount(raw)
	if err != nil || acct.Registration == nil {
		return nil, "", true
	}
	u, err := url.Parse(acct.Registration.URI)
	if err != nil {
		return nil, "", true
	}
	switch u.Hostname() {
	case productionHost:
		return raw, DirectoryProduction, true
	case stagingHost:
		return raw, DirectoryStaging, true
	}
	return nil, "", true
}
