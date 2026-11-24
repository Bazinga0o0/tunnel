package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/server/acme"
	"github.com/Bazinga0o0/tunnel/internal/server/config"
	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
	"github.com/Bazinga0o0/tunnel/internal/server/tlsutil"
)

// acmeIssuer replaces Let's Encrypt in tests; nil in production.
var acmeIssuer acme.Issuer

// buildTLSConfig returns a *tls.Config plus (optionally) an *acme.Manager
// whose RenewalLoop the caller should run on a context-scoped goroutine. It
// logs which certificate source is active; the warning about a
// self-signed certificate in database mode comes with the config warnings.
//
// With ACME and no usable cached certificate it waits until one is obtained
// (retrying with the backoff) or ctx ends.
func buildTLSConfig(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*tls.Config, *acme.Manager, error) {
	switch {
	case cfg.TLS.ACME != nil:
		a := cfg.TLS.ACME
		mgr, err := acme.New(ctx, acme.Options{
			Email:       a.Email,
			Domains:     a.Domains,
			CacheDir:    a.CacheDir,
			DNSProvider: a.DNSProvider,
			Staging:     a.Staging,
			Logger:      logger,
			Issuer:      acmeIssuer,
		})
		if err != nil {
			return nil, nil, err
		}
		logger.Info("tls source: acme", "domains", a.Domains, "staging", a.Staging, "cache_dir", a.CacheDir)
		return &tls.Config{GetCertificate: mgr.GetCertificate, MinVersion: tls.VersionTLS12}, mgr, nil

	case cfg.TLS.CertFile != "":
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, nil, err
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", cfg.TLS.CertFile, err)
		}
		metrics.CertNotAfter.Set(float64(leaf.NotAfter.Unix()))
		logger.Info("tls source: certificate files", "cert_file", cfg.TLS.CertFile, "not_after", leaf.NotAfter)
		if !time.Now().Before(leaf.NotAfter) {
			logger.Warn("tls: the certificate file has expired", "cert_file", cfg.TLS.CertFile, "not_after", leaf.NotAfter)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil, nil

	default:
		certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert(cfg.TLS.SelfSignedHosts)
		if err != nil {
			return nil, nil, err
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, nil, err
		}
		logger.Info("tls source: self-signed certificate (development only)", "hosts", cfg.TLS.SelfSignedHosts)
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil, nil
	}
}
