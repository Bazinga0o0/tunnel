package acme

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/registration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeACMEClient stands for a lego client that reached the CA.
type fakeACMEClient struct {
	t         *testing.T
	registers *atomic.Int32
}

func (f fakeACMEClient) Register() (*registration.Resource, error) {
	f.registers.Add(1)
	return &registration.Resource{URI: "https://" + productionHost + "/acme/acct/7"}, nil
}

func (f fakeACMEClient) Obtain(domains []string) ([]byte, []byte, error) {
	c, k := genCert(f.t, domains, time.Now().Add(-time.Minute), time.Now().Add(90*24*time.Hour))
	return c, k, nil
}

// withFakeCA replaces the connection to the CA and the DNS provider, and
// lets the test fail the writes of the account file.
func withFakeCA(t *testing.T) (registers *atomic.Int32, failAccountWrites *atomic.Bool) {
	t.Helper()
	registers, failAccountWrites = &atomic.Int32{}, &atomic.Bool{}
	prevConnect, prevProvider, prevTemp := connectACME, newDNSProvider, createTemp
	connectACME = func(*acmeAccount, string, challenge.Provider) (acmeClient, error) {
		return fakeACMEClient{t: t, registers: registers}, nil
	}
	newDNSProvider = func(string) (challenge.Provider, error) { return nil, nil }
	createTemp = func(dir, pattern string) (*os.File, error) {
		if failAccountWrites.Load() && strings.Contains(pattern, accountFile) {
			return nil, fs.ErrPermission
		}
		return os.CreateTemp(dir, pattern)
	}
	t.Cleanup(func() { connectACME, newDNSProvider, createTemp = prevConnect, prevProvider, prevTemp })
	return registers, failAccountWrites
}

// Saving the account after the CA registered it happens after CA contact:
// a failure goes through the backoff and does not end the start.
func TestSavingTheRegisteredAccountGoesThroughTheBackoff(t *testing.T) {
	registers, failAccountWrites := withFakeCA(t)
	m, _, _ := newTestManager(t, t.TempDir(), false, nil)
	m.newIssuer = func(dir, directory string) (Issuer, error) { return newLegoIssuer(m.opts, dir, directory) }
	fc := m.clk.(*fakeClock)

	// The new account key is written, then the disk fills up.
	iss, err := newLegoIssuer(m.opts, m.dir, m.directory)
	require.NoError(t, err)
	m.issuer = iss
	failAccountWrites.Store(true)

	done := startAsync(m, context.Background())
	assert.Equal(t, BackoffMin, fc.nextWait(t), "a transient failure: wait and try again")
	assert.Equal(t, int32(1), registers.Load())

	failAccountWrites.Store(false)
	fc.Advance(BackoffMin)
	require.NoError(t, requireResult(t, done))
	assert.Equal(t, int32(2), registers.Load(), "registered again with the same key")
	assert.FileExists(t, m.dir+string(os.PathSeparator)+accountFile)
}

// Writing a newly created account key is local, but waiting can cure it:
// not permanent either.
func TestWritingANewAccountKeyIsNotPermanent(t *testing.T) {
	_, failAccountWrites := withFakeCA(t)
	failAccountWrites.Store(true)
	_, err := newLegoIssuer(Options{Email: "ops@example.com", DNSProvider: "ionos"}, t.TempDir(), DirectoryProduction)
	require.Error(t, err)
	assert.False(t, isPermanent(err))
}

// Creating the issuer does not contact the CA; connecting is part of the
// first attempt.
func TestNewLegoIssuerDoesNotConnect(t *testing.T) {
	registers, _ := withFakeCA(t)
	connected := false
	connectACME = func(*acmeAccount, string, challenge.Provider) (acmeClient, error) {
		connected = true
		return fakeACMEClient{t: t, registers: registers}, nil
	}
	iss, err := newLegoIssuer(Options{Email: "ops@example.com", DNSProvider: "ionos"}, t.TempDir(), DirectoryProduction)
	require.NoError(t, err)
	assert.False(t, connected)
	_, _, err = iss.Obtain(testDomains)
	require.NoError(t, err)
	assert.True(t, connected)
}
