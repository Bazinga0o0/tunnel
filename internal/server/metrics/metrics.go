// Package metrics exposes Prometheus counters / gauges for tunneld.
// Metrics are served on a private, loopback-only HTTP listener so operators
// can scrape via SSH tunnel without authentication concerns.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// ActiveSessions tracks currently-registered tunnel sessions.
	// Labels: type = "http" | "tcp".
	ActiveSessions = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tunneld_active_sessions",
			Help: "Currently active tunnel sessions, labelled by type.",
		},
		[]string{"type"},
	)

	// RequestTotal counts proxied requests by type and outcome.
	// Labels: type = "http" | "tcp"; status = free-form ("proxied", "not_found", ...).
	RequestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunneld_request_total",
			Help: "Total proxied requests, labelled by type and status.",
		},
		[]string{"type", "status"},
	)

	// AuthAttemptsTotal counts tunnel-client auth attempts.
	// Labels: result = "success" | "fail".
	AuthAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunneld_auth_attempts_total",
			Help: "Tunnel-client auth attempts.",
		},
		[]string{"result"},
	)

	// CertRenewalLast is the Unix timestamp of the last successful ACME renewal.
	CertRenewalLast = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "tunneld_cert_renewal_last_unix",
			Help: "Unix timestamp of the last successful ACME renewal. 0 if none this process lifetime.",
		},
	)

	// CertNotAfter is the expiry (NotAfter) of the certificate the server
	// presents, as a Unix timestamp, for alerting before it runs out. Set
	// for ACME certificates and certificate files; 0 when unknown.
	CertNotAfter = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "tunneld_cert_not_after_unix",
			Help: "Unix timestamp at which the served TLS certificate expires (ACME or certificate file). 0 if unknown.",
		},
	)
)

func init() {
	prometheus.MustRegister(ActiveSessions, RequestTotal, AuthAttemptsTotal, CertRenewalLast, CertNotAfter)
}
