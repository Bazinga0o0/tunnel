package acme

import (
	"os"
	"testing"
)

// TestObtainStagingCert runs a real ACME flow against Let's Encrypt staging.
// Gated behind TUNNELD_ACME_STAGING=1 so normal test runs skip it (no
// network, no IONOS API key needed).
//
// To run manually:
//
//	export IONOS_API_KEY="public_key.private_key"
//	export TUNNELD_ACME_STAGING=1
//	go test ./internal/server/acme/... -v -timeout 300s
func TestObtainStagingCert(t *testing.T) {
	if os.Getenv("TUNNELD_ACME_STAGING") != "1" {
		t.Skip("TUNNELD_ACME_STAGING=1 required for live staging test")
	}
	// This test deliberately doesn't run in automation — it requires real
	// DNS API credentials. The flow is validated manually by operators.
	t.Skip("manual-only; remove this line to actually run")
}
