package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	hosts := []string{"tunnel.localhost", "*.localhost"}
	certPEM, keyPEM, err := GenerateSelfSignedCert(hosts)
	require.NoError(t, err)
	require.NotEmpty(t, certPEM)
	require.NotEmpty(t, keyPEM)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	require.Len(t, cert.Certificate, 1)

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Contains(t, parsed.DNSNames, "tunnel.localhost")
	assert.Contains(t, parsed.DNSNames, "*.localhost")
}
