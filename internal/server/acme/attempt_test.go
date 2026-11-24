package acme

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- a damaged or implausible marker (point 1) ----

// renewalDue writes a cached certificate that is inside the renewal window
// and returns a manager on it, started.
func renewalDue(t *testing.T, iss Issuer) (*Manager, *fakeClock) {
	t.Helper()
	cacheDir := t.TempDir()
	certPEM, keyPEM := validCert(t, 10*24*time.Hour)
	writeCacheFiles(t, filepath.Join(cacheDir, "production"), certPEM, keyPEM, DirectoryProduction)
	m, _, _ := newTestManager(t, cacheDir, false, iss)
	require.NoError(t, m.start(context.Background()))
	return m, m.clk.(*fakeClock)
}

func TestDamagedMarkerIsRepairedOnTheRenewalPath(t *testing.T) {
	for name, content := range map[string]string{"garbage": "{garbage", "empty": "", "empty object": "{}"} {
		t.Run(name, func(t *testing.T) {
			iss := &fakeIssuer{t: t}
			m, fc := renewalDue(t, iss)
			iss.now = fc.Now
			require.NoError(t, os.WriteFile(filepath.Join(m.dir, backoffFile), []byte(content), 0o600))

			m.checkRenewal(context.Background())
			assert.Zero(t, iss.callCount(), "the damaged marker counts as an attempt just now")
			repaired := readMarker(t, m.dir)
			assert.Equal(t, BackoffMin, repaired.Step, "replaced by a valid marker")

			fc.Advance(BackoffMin)
			m.checkRenewal(context.Background())
			assert.Equal(t, 1, iss.callCount(), "after the shortest wait the renewal is attempted")
		})
	}
}

func TestImplausibleMarkerIsClamped(t *testing.T) {
	// An attempt "in the future" counts as now.
	iss := &fakeIssuer{t: t}
	m, fc := renewalDue(t, iss)
	iss.now = fc.Now
	writeMarker(t, m.dir, backoffState{LastAttempt: fc.Now().Add(10 * time.Hour), Step: BackoffMin})
	m.checkRenewal(context.Background())
	assert.Zero(t, iss.callCount())
	fc.Advance(BackoffMin)
	m.checkRenewal(context.Background())
	assert.Equal(t, 1, iss.callCount(), "the future time was clamped to now")

	// A step of many hours is cut to the longest step.
	iss = &fakeIssuer{t: t}
	m, fc = renewalDue(t, iss)
	iss.now = fc.Now
	writeMarker(t, m.dir, backoffState{LastAttempt: fc.Now().Add(-61 * time.Minute), Step: 30 * time.Hour})
	m.checkRenewal(context.Background())
	assert.Equal(t, 1, iss.callCount(), "a step over an hour counts as an hour")
}

// ---- the marker goes only when the certificate is cached (round 3) ----

// A certificate that was obtained but could not be cached keeps the marker:
// a restart that finds no cache must not order again without the wait.
func TestMarkerStaysWhenTheCertificateCannotBeCached(t *testing.T) {
	prev := createTemp
	createTemp = func(dir, pattern string) (*os.File, error) {
		for _, name := range []string{certFile, keyFile, metaFile} {
			if strings.Contains(pattern, name) {
				return nil, fs.ErrPermission
			}
		}
		return os.CreateTemp(dir, pattern)
	}
	defer func() { createTemp = prev }()

	iss := &fakeIssuer{t: t}
	m, _, log := newTestManager(t, t.TempDir(), false, iss)
	require.NoError(t, m.start(context.Background()))
	assert.Equal(t, iss.issued[0], servedSerial(t, m), "the certificate is served all the same")
	assert.FileExists(t, filepath.Join(m.dir, backoffFile))
	assert.Contains(t, log.String(), "could not be cached")
}

// ---- the disk is consulted again before every attempt (round 3) ----

// Another process on the same directory obtained a certificate while this
// one waited: it is used, nothing is ordered.
func TestCertificateThatAppearsDuringTheWaitIsUsed(t *testing.T) {
	cacheDir := t.TempDir()
	m, created, _ := newTestManager(t, cacheDir, false, failingIssuer{t})
	fc := m.clk.(*fakeClock)
	writeMarker(t, m.dir, backoffState{LastAttempt: fc.Now(), Step: BackoffMin})
	done := startAsync(m, context.Background())
	assert.Equal(t, BackoffMin, fc.nextWait(t))

	certPEM, keyPEM := validCert(t, 60*24*time.Hour)
	writeCacheFiles(t, m.dir, certPEM, keyPEM, DirectoryProduction)
	fc.Advance(BackoffMin)
	require.NoError(t, requireResult(t, done))
	assert.Zero(t, *created, "no CA contact")
	assert.Equal(t, serialOf(t, certPEM), servedSerial(t, m))
}

// The renewal takes a fresh certificate another process cached instead of
// ordering one.
func TestRenewalUsesACertificateAnotherProcessCached(t *testing.T) {
	m, _ := renewalDue(t, failingIssuer{t})
	fresh, freshKey := validCert(t, 80*24*time.Hour)
	writeCacheFiles(t, m.dir, fresh, freshKey, DirectoryProduction)
	m.checkRenewal(context.Background())
	assert.Equal(t, serialOf(t, fresh), servedSerial(t, m))
}

// On the renewal path an unreadable metadata file does not stop the
// renewal: the attempt goes on and its cache write repairs the file.
func TestRenewalRepairsAnUnreadableMetadataFile(t *testing.T) {
	iss := &fakeIssuer{t: t}
	m, fc := renewalDue(t, iss)
	iss.now = fc.Now
	require.NoError(t, os.WriteFile(filepath.Join(m.dir, metaFile), []byte("{garbled"), 0o600))

	m.checkRenewal(context.Background())
	require.Equal(t, 1, iss.callCount())
	assert.Equal(t, iss.issued[0], servedSerial(t, m))
	raw, err := os.ReadFile(filepath.Join(m.dir, metaFile))
	require.NoError(t, err)
	var meta certMeta
	require.NoError(t, json.Unmarshal(raw, &meta), "the metadata was rewritten")
	assert.Equal(t, DirectoryProduction, meta.Directory)
}

// Another process made an attempt while this one waited: its newer marker
// extends the wait.
func TestNewerMarkerOnDiskExtendsTheWait(t *testing.T) {
	iss := &fakeIssuer{t: t}
	m, _, _ := newTestManager(t, t.TempDir(), false, iss)
	fc := m.clk.(*fakeClock)
	iss.now = fc.Now
	writeMarker(t, m.dir, backoffState{LastAttempt: fc.Now(), Step: BackoffMin})
	done := startAsync(m, context.Background())
	assert.Equal(t, BackoffMin, fc.nextWait(t))

	fc.Advance(50 * time.Second)
	writeMarker(t, m.dir, backoffState{LastAttempt: fc.Now(), Step: 2 * BackoffMin})
	fc.Advance(10 * time.Second)
	assert.Equal(t, 110*time.Second, fc.nextWait(t), "the rest of the other process's wait")
	assert.Zero(t, iss.callCount())
	fc.Advance(110 * time.Second)
	require.NoError(t, requireResult(t, done))
	assert.Equal(t, 1, iss.callCount())
}

// ---- the attempt is on disk before the CA is contacted (point 2) ----

// blockingIssuer blocks in Obtain until released, like a lego call that
// cannot be cancelled, and then fails.
type blockingIssuer struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	calls   int
}

func newBlockingIssuer() *blockingIssuer {
	return &blockingIssuer{entered: make(chan struct{}), release: make(chan struct{})}
}

func (b *blockingIssuer) Obtain([]string) ([]byte, []byte, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return nil, nil, errors.New("connection reset")
}

func (b *blockingIssuer) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-b.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the issuer was not called")
	}
}

// A process that dies in the middle of an attempt leaves the marker: the
// next process does not contact the CA inside the window.
func TestCrashDuringAnAttemptKeepsTheBackoff(t *testing.T) {
	cacheDir := t.TempDir()
	first := newBlockingIssuer()
	defer close(first.release)
	m1, _, _ := newTestManager(t, cacheDir, false, first)
	fc1 := m1.clk.(*fakeClock)
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	go func() { _ = m1.start(ctx1) }()
	first.waitEntered(t)

	// The first process is gone (abandoned); a new one starts 20 s later.
	second := &fakeIssuer{t: t}
	m2, created, _ := newTestManager(t, cacheDir, false, second)
	fc2 := m2.clk.(*fakeClock)
	fc2.Advance(fc1.Now().Add(20 * time.Second).Sub(fc2.Now()))
	second.now = fc2.Now
	done := startAsync(m2, context.Background())
	assert.Equal(t, 40*time.Second, fc2.nextWait(t), "the rest of the first step")
	assert.Zero(t, *created+second.callCount(), "no CA contact inside the window")
	fc2.Advance(40 * time.Second)
	require.NoError(t, requireResult(t, done))
	assert.Equal(t, 1, second.callCount())
}

func TestShutdownDuringAnAttemptLeavesTheMarker(t *testing.T) {
	iss := newBlockingIssuer()
	m, _, _ := newTestManager(t, t.TempDir(), false, iss)
	ctx, cancel := context.WithCancel(context.Background())
	done := startAsync(m, ctx)
	iss.waitEntered(t)
	cancel()
	close(iss.release)
	assert.ErrorIs(t, requireResult(t, done), context.Canceled)
	assert.Equal(t, BackoffMin, readMarker(t, m.dir).Step, "the attempt that was cut off counts")
}

func TestNoCAContactWhenTheMarkerCannotBeWritten(t *testing.T) {
	prev := createTemp
	createTemp = func(dir, pattern string) (*os.File, error) {
		if strings.Contains(pattern, backoffFile) {
			return nil, fs.ErrPermission
		}
		return os.CreateTemp(dir, pattern)
	}
	defer func() { createTemp = prev }()

	iss := &fakeIssuer{t: t}
	m, _, _ := newTestManager(t, t.TempDir(), false, iss)
	fc := m.clk.(*fakeClock)
	ctx, cancel := context.WithCancel(context.Background())
	done := startAsync(m, ctx)
	assert.Equal(t, BackoffMin, fc.nextWait(t), "it waits as after a failed attempt")
	assert.Zero(t, iss.callCount(), "no CA contact without the marker on disk")
	cancel()
	assert.ErrorIs(t, requireResult(t, done), context.Canceled)
}
