// Package acme manages a Let's Encrypt wildcard certificate via DNS-01.
// Currently supports the IONOS DNS provider.
//
// The certificate is cached on disk, one directory per ACME directory
// (production and staging never share a cache or an account). A cached
// certificate is used only while it is valid for the configured domains and
// was issued by the configured directory; with such a certificate the server
// starts without contacting the ACME directory at all. The ACME client is
// created the first time a certificate has to be obtained.
//
// Every attempt that contacts the CA goes through a backoff that is kept in
// the cache directory: after a failure the next attempt waits 1 minute,
// doubling up to 1 hour, also across restarts of the process. A failed
// first certificate does not end the process; it keeps trying.
package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v4/lego"

	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
)

// The ACME directories.
const (
	DirectoryProduction = lego.LEDirectoryProduction
	DirectoryStaging    = lego.LEDirectoryStaging
)

const (
	// RenewalCheckInterval is the time between two renewal checks. The
	// first check runs when RenewalLoop starts.
	RenewalCheckInterval = 12 * time.Hour
	// RenewBefore is how long before its expiry a certificate is renewed.
	RenewBefore = 30 * 24 * time.Hour
	// UrgentWindow and UrgentCheckInterval: in the last three days before
	// expiry the renewal is checked every hour instead of every 12 hours,
	// still subject to the backoff after a failure.
	UrgentWindow        = 3 * 24 * time.Hour
	UrgentCheckInterval = time.Hour
)

// Options configure the ACME manager.
type Options struct {
	Email       string
	Domains     []string // e.g. ["example.org", "*.example.org"]
	CacheDir    string
	DNSProvider string // "ionos"
	Staging     bool
	Logger      *slog.Logger

	// Issuer obtains certificates. nil selects Let's Encrypt through lego
	// with the configured DNS provider, which is what production uses.
	Issuer Issuer
}

// Issuer obtains a certificate for the domains from a CA and returns the
// certificate chain and its private key in PEM.
type Issuer interface {
	Obtain(domains []string) (certPEM, keyPEM []byte, err error)
}

// served is the certificate the manager hands out.
type served struct {
	cert     *tls.Certificate
	notAfter time.Time
}

// Manager obtains + auto-renews a TLS certificate via ACME DNS-01.
type Manager struct {
	opts      Options
	logger    *slog.Logger
	dir       string // cache directory of the configured ACME directory
	directory string // URL of the configured ACME directory

	current atomic.Pointer[served]

	// obtainMu serializes obtain; see there.
	obtainMu sync.Mutex
	issuer   Issuer // created by newIssuer on first use
	// newIssuer creates the issuer for the cache directory and ACME
	// directory it is given. Tests replace it.
	newIssuer func(dir, directory string) (Issuer, error)

	checkInterval time.Duration
	clk           clock
}

// permanentError marks an error that waiting does not cure (an unreadable
// account file, a missing DNS provider key). It ends the start instead of
// being retried.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

func permanent(err error) error { return permanentError{err: err} }

func isPermanent(err error) bool {
	var p permanentError
	return errors.As(err, &p)
}

// New sets up the manager. It uses the cached certificate when it is valid
// (after migrating the cache of the previous version once); otherwise it
// obtains a new one, retrying with the backoff until it succeeds or ctx
// ends. It returns an error for problems that waiting does not cure: a cache
// directory that cannot be written, an unreadable account or metadata file,
// a DNS provider without credentials.
func New(ctx context.Context, opts Options) (*Manager, error) {
	m, err := newManager(opts)
	if err != nil {
		return nil, err
	}
	if opts.Issuer != nil {
		m.newIssuer = func(string, string) (Issuer, error) { return opts.Issuer, nil }
	}
	if err := m.start(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// newManager checks the options and prepares the cache directory. It neither
// reads the cache nor contacts anybody.
func newManager(opts Options) (*Manager, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	switch {
	case len(opts.Domains) == 0:
		return nil, errors.New("acme: Domains must not be empty")
	case opts.Email == "":
		return nil, errors.New("acme: Email is required")
	case opts.CacheDir == "":
		return nil, errors.New("acme: CacheDir is required")
	case opts.DNSProvider != "ionos":
		return nil, fmt.Errorf("acme: unsupported dns_provider %q", opts.DNSProvider)
	}
	m := &Manager{
		opts:          opts,
		logger:        opts.Logger,
		directory:     DirectoryProduction,
		dir:           filepath.Join(opts.CacheDir, "production"),
		checkInterval: RenewalCheckInterval,
		clk:           realClock{},
	}
	if opts.Staging {
		m.directory = DirectoryStaging
		m.dir = filepath.Join(opts.CacheDir, "staging")
	}
	m.newIssuer = func(dir, directory string) (Issuer, error) {
		return newLegoIssuer(m.opts, dir, directory)
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, fmt.Errorf("acme: create cache directory: %w", err)
	}
	return m, nil
}

// start loads the cached certificate or obtains a new one.
func (m *Manager) start(ctx context.Context) error {
	if m.opts.Staging {
		m.logger.Warn("acme: the Let's Encrypt staging directory is in use; browsers and tunnel clients do not trust its certificates",
			"directory", m.directory)
	}
	// Before any contact with the CA: a certificate that cannot be cached
	// would be ordered again at every start, into the CA's limit for
	// duplicate certificates.
	if err := probeWritable(m.dir); err != nil {
		return fmt.Errorf("acme: the cache directory %s is not writable: %w", m.dir, err)
	}
	if !hasCertSet(m.dir) {
		m.migrateOldCache()
	}
	cert, notAfter, err := loadCachedCert(m.dir, m.opts.Domains, m.directory, m.clk.Now())
	switch {
	case err == nil:
		m.store(cert, notAfter)
		m.logger.Info("acme: using the cached certificate", "domains", m.opts.Domains, "not_after", notAfter)
		return nil
	case errors.Is(err, errCacheUnreadable):
		return fmt.Errorf("acme: %w", err)
	case errors.Is(err, errCacheCorrupt):
		// The cache write replaces the file once a certificate is obtained.
		m.logger.Warn("acme: the cached certificate's metadata file does not parse; treating the cache as empty",
			"file", filepath.Join(m.dir, metaFile), "err", err.Error())
	}
	m.logger.Info("acme: no usable cached certificate, requesting a new one", "reason", err.Error(), "domains", m.opts.Domains)
	return m.obtainWithBackoff(ctx)
}

// obtainWithBackoff obtains a certificate, waiting out the backoff before
// every attempt, until it succeeds, a permanent error occurs or ctx ends.
// Before each attempt it looks at the directory again: a usable certificate
// that another process cached meanwhile is taken instead of ordering one,
// and a marker that another process wrote meanwhile extends the wait.
func (m *Manager) obtainWithBackoff(ctx context.Context) error {
	b := m.readBackoff()
	for {
		if wait := b.next().Sub(m.clk.Now()); wait > 0 {
			m.logger.Warn("acme: waiting before the next attempt to obtain a certificate",
				"next_attempt", b.next().UTC().Format(time.RFC3339), "backoff", b.Step)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-m.clk.After(wait):
			}
		}
		if done, err := m.useCachedIfValid(false); done || err != nil {
			return err
		}
		if disk := m.readBackoff(); disk.next().After(b.next()) {
			b = disk
			continue
		}
		next, err := m.attempt(ctx, b)
		switch {
		case err == nil:
			return nil
		case ctx.Err() != nil:
			return ctx.Err()
		case isPermanent(err):
			return fmt.Errorf("acme: %w", err)
		}
		b = next
		m.logger.Error("acme: obtaining a certificate failed; the server starts once one is obtained",
			"err", err, "next_attempt", b.next().UTC().Format(time.RFC3339), "backoff", b.Step)
	}
}

// useCachedIfValid serves the cached certificate when it is usable and, with
// fresh, not due for renewal either. It reports whether it did; the error is
// that of a cache file that cannot be read.
func (m *Manager) useCachedIfValid(fresh bool) (bool, error) {
	cert, notAfter, err := loadCachedCert(m.dir, m.opts.Domains, m.directory, m.clk.Now())
	switch {
	case errors.Is(err, errCacheUnreadable):
		return false, fmt.Errorf("acme: %w", err)
	case err != nil:
		return false, nil
	case fresh && notAfter.Sub(m.clk.Now()) <= RenewBefore:
		return false, nil
	}
	m.store(cert, notAfter)
	m.logger.Info("acme: using the certificate another process cached", "not_after", notAfter)
	return true, nil
}

func (m *Manager) store(cert *tls.Certificate, notAfter time.Time) {
	m.current.Store(&served{cert: cert, notAfter: notAfter})
	metrics.CertNotAfter.Set(float64(notAfter.Unix()))
}

// GetCertificate is the tls.Config hook.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s := m.current.Load()
	if s == nil {
		return nil, errors.New("acme: no certificate available yet")
	}
	return s.cert, nil
}

// RenewalLoop checks the certificate at once and then every 12 hours (every
// hour in the last three days before expiry), and renews it when it expires
// within 30 days. A failed renewal keeps the current certificate; the next
// attempt also waits for the backoff. Call from a goroutine; it returns when
// ctx ends.
func (m *Manager) RenewalLoop(ctx context.Context) {
	for {
		m.checkRenewal(ctx)
		select {
		case <-ctx.Done():
			return
		case <-m.clk.After(m.nextCheckIn()):
		}
	}
}

// nextCheckIn returns the time until the next renewal check.
func (m *Manager) nextCheckIn() time.Duration {
	if s := m.current.Load(); s != nil && s.notAfter.Sub(m.clk.Now()) <= UrgentWindow {
		return UrgentCheckInterval
	}
	return m.checkInterval
}

// checkRenewal renews the certificate when it expires within RenewBefore and
// the backoff allows an attempt.
func (m *Manager) checkRenewal(ctx context.Context) {
	now := m.clk.Now()
	s := m.current.Load()
	if s != nil && s.notAfter.Sub(now) > RenewBefore {
		return
	}
	if ctx.Err() != nil {
		return
	}
	var notAfter time.Time
	if s != nil {
		notAfter = s.notAfter
	}
	b := m.readBackoff()
	if next := b.next(); next.After(now) {
		m.logger.Info("acme: renewal due, waiting for the backoff", "not_after", notAfter,
			"next_attempt", next.UTC().Format(time.RFC3339))
		return
	}
	// Another process on the same directory may have renewed already. A
	// cache file that cannot be read is no fresh certificate: the renewal
	// goes on, and its cache write replaces the file.
	if done, err := m.useCachedIfValid(true); done {
		return
	} else if err != nil {
		m.logger.Warn("acme: the cached certificate cannot be read; renewing anyway", "err", err)
	}
	m.logger.Info("acme: the certificate expires soon, renewing", "not_after", notAfter)
	if _, err := m.attempt(ctx, b); err != nil {
		// The next renewal check is when the loop wakes up; an attempt then
		// also waits for the marker on disk.
		m.logger.Error("acme: certificate renewal failed; the current certificate stays in use",
			"err", err, "not_after", notAfter, "next_check", m.clk.Now().Add(m.nextCheckIn()).UTC().Format(time.RFC3339))
	}
}

// obtain makes one attempt with the backoff state on disk, without waiting
// for it.
func (m *Manager) obtain(ctx context.Context) error {
	_, err := m.attempt(ctx, m.readBackoff())
	return err
}

// attempt makes one attempt to obtain a certificate after the backoff state
// prev, serves the certificate and caches it. It returns the backoff state
// that follows: none after a success, otherwise the attempt just made with
// the next wait.
//
// The marker for this attempt is written before the CA is contacted, and the
// CA is not contacted when it cannot be written: a process that dies during
// the attempt, or a context that ends while lego cannot be stopped, leaves
// the marker behind, and the next process waits. It is removed once the
// new certificate is cached; a certificate that could not be cached keeps it.
//
// Concurrency: obtainMu serializes callers so a manually-triggered attempt
// cannot race RenewalLoop. Note that lego's Certificate.Obtain does NOT
// accept a context and cannot be cancelled — a stuck call will hold the
// mutex and block shutdown until the underlying HTTP/DNS propagation
// timeouts fire (typically many minutes). The elapsed-time log below gives
// operators a signal to watch for stuck renewals.
func (m *Manager) attempt(ctx context.Context, prev backoffState) (backoffState, error) {
	m.obtainMu.Lock()
	defer m.obtainMu.Unlock()
	next := backoffState{LastAttempt: m.clk.Now(), Step: prev.nextStep()}
	if ctx.Err() != nil {
		return prev, ctx.Err()
	}
	if m.issuer == nil {
		// Local only: the issuer contacts the CA in Obtain.
		iss, err := m.newIssuer(m.dir, m.directory)
		if err != nil {
			return next, fmt.Errorf("acme client: %w", err)
		}
		m.issuer = iss
	}
	if err := m.writeBackoff(next); err != nil {
		return next, fmt.Errorf("the backoff marker cannot be written, the CA was not contacted: %w", err)
	}
	start := time.Now()
	certPEM, keyPEM, err := m.issuer.Obtain(m.opts.Domains)
	if err != nil {
		m.logger.Warn("acme: obtain failed", "elapsed", time.Since(start), "err", err)
		return next, fmt.Errorf("obtain: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return next, fmt.Errorf("parse the new certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return next, fmt.Errorf("parse the new certificate: %w", err)
	}
	if m.directory == DirectoryProduction && isStagingIssuer(leaf) {
		return next, errors.New("the CA returned a staging certificate for the production directory")
	}
	m.store(&cert, leaf.NotAfter)
	metrics.CertRenewalLast.Set(float64(time.Now().Unix()))
	m.logger.Info("acme: certificate obtained", "domains", m.opts.Domains, "not_after", leaf.NotAfter, "elapsed", time.Since(start))

	// The certificate is served even if it cannot be cached (the directory
	// was writable at start-up). The marker goes only once the cache holds
	// it: a restart that finds no cache then still waits before it orders
	// again; a marker next to a valid cache does no harm.
	meta := certMeta{Directory: m.directory, Domains: m.opts.Domains, ObtainedAt: time.Now().UTC()}
	if err := writeCache(m.dir, certPEM, keyPEM, meta); err != nil {
		m.logger.Error("acme: the new certificate could not be cached; the backoff marker stays", "dir", m.dir, "err", err)
		return backoffState{}, nil
	}
	m.clearBackoff()
	return backoffState{}, nil
}
