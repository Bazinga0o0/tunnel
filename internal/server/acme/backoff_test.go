package acme

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startAsync runs m.start in a goroutine and returns its result channel.
func startAsync(m *Manager, ctx context.Context) <-chan error {
	done := make(chan error, 1)
	go func() { done <- m.start(ctx) }()
	return done
}

func requireResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("start did not return")
		return nil
	}
}

func readMarker(t *testing.T, dir string) backoffState {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, backoffFile))
	require.NoError(t, err)
	var b backoffState
	require.NoError(t, json.Unmarshal(raw, &b))
	return b
}

func writeMarker(t *testing.T, dir string, b backoffState) {
	t.Helper()
	raw, err := json.Marshal(b)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, backoffFile), raw, 0o600))
}

// A first certificate that cannot be obtained does not end the process: it
// is tried again after 1, 2, 4 ... minutes, at most every 60 minutes.
func TestFailedObtainRetriesWithBackoff(t *testing.T) {
	iss := &fakeIssuer{t: t, err: errors.New("CA unreachable")}
	m, _, log := newTestManager(t, t.TempDir(), false, iss)
	fc := m.clk.(*fakeClock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startAsync(m, ctx)

	var waits []time.Duration
	for i := 0; i < 8; i++ {
		d := fc.nextWait(t)
		waits = append(waits, d)
		assert.Equal(t, i+1, iss.callCount(), "one attempt before each wait")
		assert.Equal(t, d, readMarker(t, m.dir).Step, "the step is on disk")
		fc.Advance(d)
	}
	assert.Equal(t, []time.Duration{
		time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
		16 * time.Minute, 32 * time.Minute, 60 * time.Minute, 60 * time.Minute,
	}, waits)
	assert.Contains(t, log.String(), "next_attempt=")

	// Shutdown during a wait ends start promptly.
	fc.nextWait(t)
	cancel()
	assert.ErrorIs(t, requireResult(t, done), context.Canceled)
}

// The marker survives the process: a restart inside the wait does not
// contact the CA before the wait is over.
func TestRestartInsideTheBackoffWindowWaits(t *testing.T) {
	cacheDir := t.TempDir()
	iss := &fakeIssuer{t: t}
	m, created, _ := newTestManager(t, cacheDir, false, iss)
	fc := m.clk.(*fakeClock)
	iss.now = fc.Now
	writeMarker(t, m.dir, backoffState{LastAttempt: fc.Now().Add(-30 * time.Second), Step: time.Minute})

	done := startAsync(m, context.Background())
	assert.Equal(t, 30*time.Second, fc.nextWait(t), "the rest of the minute")
	assert.Zero(t, *created, "no CA contact inside the backoff")
	assert.Zero(t, iss.callCount())

	fc.Advance(30 * time.Second)
	require.NoError(t, requireResult(t, done))
	assert.Equal(t, 1, iss.callCount())
	assert.NoFileExists(t, filepath.Join(m.dir, backoffFile), "a success removes the marker")
}

func TestSuccessAfterFailuresClearsTheMarker(t *testing.T) {
	iss := &fakeIssuer{t: t, err: errors.New("CA unreachable")}
	m, _, _ := newTestManager(t, t.TempDir(), false, iss)
	fc := m.clk.(*fakeClock)
	iss.now = fc.Now
	done := startAsync(m, context.Background())

	d := fc.nextWait(t)
	assert.FileExists(t, filepath.Join(m.dir, backoffFile))
	iss.mu.Lock()
	iss.err = nil
	iss.mu.Unlock()
	fc.Advance(d)
	require.NoError(t, requireResult(t, done))
	assert.NoFileExists(t, filepath.Join(m.dir, backoffFile))
	assert.Equal(t, iss.issued[0], servedSerial(t, m))
}

func TestDamagedMarkerWaitsTheShortestBackoff(t *testing.T) {
	iss := &fakeIssuer{t: t}
	m, _, _ := newTestManager(t, t.TempDir(), false, iss)
	fc := m.clk.(*fakeClock)
	require.NoError(t, os.WriteFile(filepath.Join(m.dir, backoffFile), []byte("{garbage"), 0o600))
	done := startAsync(m, context.Background())
	assert.Equal(t, time.Minute, fc.nextWait(t))
	assert.Zero(t, iss.callCount())
	fc.Advance(time.Minute)
	require.NoError(t, requireResult(t, done))
}

// A cache directory that cannot be written is a start-up error before any
// contact with the CA; otherwise every restart would order a certificate.
func TestUnwritableCacheDirFailsBeforeTheCA(t *testing.T) {
	prev := createTemp
	createTemp = func(string, string) (*os.File, error) { return nil, fs.ErrPermission }
	defer func() { createTemp = prev }()

	m, created, _ := newTestManager(t, t.TempDir(), false, failingIssuer{t})
	err := m.start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not writable")
	assert.Zero(t, *created)
}

func TestUnwritableCacheDirOnDisk(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory modes do not stop this user here")
	}
	m, created, _ := newTestManager(t, t.TempDir(), false, failingIssuer{t})
	require.NoError(t, os.Chmod(m.dir, 0o500))
	defer func() { _ = os.Chmod(m.dir, 0o700) }()
	require.Error(t, m.start(context.Background()))
	assert.Zero(t, *created)
}

// Renewal goes through the same marker, and close to expiry it is checked
// every hour instead of every 12 hours.
func TestRenewalAfterAFailureUsesTheBackoffAndHourlyChecksNearExpiry(t *testing.T) {
	cacheDir := t.TempDir()
	certPEM, keyPEM := validCert(t, 2*24*time.Hour) // inside the last three days
	writeCacheFiles(t, filepath.Join(cacheDir, "production"), certPEM, keyPEM, DirectoryProduction)
	iss := &fakeIssuer{t: t, err: errors.New("dns provider down")}
	m, _, _ := newTestManager(t, cacheDir, false, iss)
	fc := m.clk.(*fakeClock)
	require.NoError(t, m.start(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.RenewalLoop(ctx)
	}()
	assert.Equal(t, UrgentCheckInterval, fc.nextWait(t), "close to expiry: the next check in an hour")
	assert.Equal(t, 1, iss.callCount())
	assert.Equal(t, time.Minute, readMarker(t, m.dir).Step)
	fc.Advance(UrgentCheckInterval)
	assert.Equal(t, UrgentCheckInterval, fc.nextWait(t))
	assert.Equal(t, 2, iss.callCount())
	assert.Equal(t, 2*time.Minute, readMarker(t, m.dir).Step)
	cancel()
	fc.Advance(UrgentCheckInterval)
	<-done
	assert.Equal(t, serialOf(t, certPEM), servedSerial(t, m), "the current certificate stays")
}

func TestRenewalOutsideTheUrgentWindowWaitsTwelveHours(t *testing.T) {
	cacheDir := t.TempDir()
	certPEM, keyPEM := validCert(t, 10*24*time.Hour)
	writeCacheFiles(t, filepath.Join(cacheDir, "production"), certPEM, keyPEM, DirectoryProduction)
	m, _, _ := newTestManager(t, cacheDir, false, &fakeIssuer{t: t, err: errors.New("down")})
	require.NoError(t, m.start(context.Background()))
	m.checkRenewal(context.Background())
	assert.Equal(t, RenewalCheckInterval, m.nextCheckIn())
}

func TestRenewalWaitsForTheBackoffMarker(t *testing.T) {
	cacheDir := t.TempDir()
	certPEM, keyPEM := validCert(t, 10*24*time.Hour)
	writeCacheFiles(t, filepath.Join(cacheDir, "production"), certPEM, keyPEM, DirectoryProduction)
	iss := &fakeIssuer{t: t}
	m, _, _ := newTestManager(t, cacheDir, false, iss)
	fc := m.clk.(*fakeClock)
	iss.now = fc.Now
	require.NoError(t, m.start(context.Background()))
	writeMarker(t, m.dir, backoffState{LastAttempt: fc.Now().Add(-10 * time.Minute), Step: time.Hour})

	m.checkRenewal(context.Background())
	assert.Zero(t, iss.callCount(), "renewal is due, but the backoff runs for 50 more minutes")
	fc.Advance(50 * time.Minute)
	m.checkRenewal(context.Background())
	assert.Equal(t, 1, iss.callCount())
	assert.NoFileExists(t, filepath.Join(m.dir, backoffFile))
}
