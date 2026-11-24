package acceptor

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// stuckSession is a session whose stream count blocks while stuck is open,
// like a yamux session whose receive loop holds the stream lock while it
// waits up to ConnectionWriteTimeout for a peer that does not read. Its
// streams are pipes.
type stuckSession struct {
	pipeSession
	mu      sync.Mutex
	stuck   chan struct{} // nil: not stuck
	entered chan struct{}
}

func newStuckSession() *stuckSession {
	return &stuckSession{entered: make(chan struct{}, 64)}
}

func (s *stuckSession) block() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stuck = make(chan struct{})
}

func (s *stuckSession) unblock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stuck != nil {
		close(s.stuck)
		s.stuck = nil
	}
}

func (s *stuckSession) NumStreams() int {
	s.mu.Lock()
	stuck := s.stuck
	s.mu.Unlock()
	if stuck != nil {
		s.entered <- struct{}{}
		<-stuck
	}
	s.pipeSession.mu.Lock()
	defer s.pipeSession.mu.Unlock()
	return 1 + len(s.peers) // the control stream and every stream handed out
}

// returnsWithin runs f and fails the test when it does not return in time.
func returnsWithin(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %s", what, d)
	}
}

// One user's session whose stream count blocks (a yamux session waiting for
// a peer that does not read) must not stall anybody else: the limiter's lock,
// which all users share, is never held while yamux is asked.
func TestAStuckSessionDoesNotStallOtherUsersOrSessions(t *testing.T) {
	u := newUserStreams(4)
	stuckUnder := newStuckSession()
	stuck := newTunnelSession("stuck", 1, 0, stuckUnder, 0)
	stuck.user = u
	first, err := stuck.OpenStream() // the stuck session is in the limiter now
	require.NoError(t, err)

	sameUserUnder := newStuckSession()
	sameUser := newTunnelSession("same-user", 1, 0, sameUserUnder, 0)
	sameUser.user = u
	_, err = sameUser.OpenStream()
	require.NoError(t, err)

	other := newTunnelSession("other", 2, 0, newStuckSession(), 0)
	other.user = u
	otherToClose := newTunnelSession("other-2", 2, 0, newStuckSession(), 0)
	otherToClose.user = u
	_, err = otherToClose.OpenStream()
	require.NoError(t, err)

	// A visitor of user 1 now waits in the stream count of the stuck session.
	stuckUnder.block()
	pending := make(chan error, 1)
	var pendingStream protocol.Stream
	go func() {
		s, err := sameUser.OpenStream()
		pendingStream = s
		pending <- err
	}()
	select {
	case <-stuckUnder.entered:
	case <-time.After(waitFor):
		t.Fatal("the open of user 1 never asked the stuck session")
	}

	// (a) another user's open, (b) another user's close, (c) another session
	// of the same user closing: none waits for the stuck session.
	returnsWithin(t, 2*time.Second, "another user's OpenStream", func() {
		_, err := other.OpenStream()
		assert.NoError(t, err)
	})
	returnsWithin(t, 2*time.Second, "another user's Close", func() { _ = otherToClose.Close() })
	thirdUnder := newStuckSession()
	third := newTunnelSession("third", 1, 0, thirdUnder, 0)
	third.user = u
	returnsWithin(t, 2*time.Second, "Close of another session of the same user", func() { _ = third.Close() })
	assert.Zero(t, u.held(2)-1, "user 2 holds the one stream of its open session")

	// (d) Once the count returns the cap holds for user 1: 4 streams.
	stuckUnder.unblock()
	select {
	case err := <-pending:
		require.NoError(t, err)
	case <-time.After(waitFor):
		t.Fatal("the pending open never finished")
	}
	require.NotNil(t, pendingStream)
	_, err = sameUser.OpenStream() // the fourth
	require.NoError(t, err)
	_, err = stuck.OpenStream()
	require.ErrorIs(t, err, ErrTooManyUserStreams, "user 1 holds 4 streams")
	assert.Equal(t, 4, u.held(1))

	require.NoError(t, first.Close())
	require.NoError(t, stuck.Close())
	require.NoError(t, sameUser.Close())
	require.NoError(t, other.Close())
	assert.Zero(t, u.held(1))
	assert.Zero(t, u.held(2))
	assert.True(t, u.users0())
}

// Streams opened while a count is under way still count: two opens that
// race each other cannot both take the last slot.
func TestConcurrentOpensOfOneUserKeepTheCap(t *testing.T) {
	u := newUserStreams(5)
	sessions := make([]*TunnelSession, 3)
	for i := range sessions {
		sessions[i] = newTunnelSession("s"+string(rune('a'+i)), 1, 0, newStuckSession(), 0)
		sessions[i].user = u
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	opened := 0
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := sessions[i%3].OpenStream(); err == nil {
				mu.Lock()
				opened++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	assert.Equal(t, 5, opened, "exactly the cap, however the opens interleave")
	assert.Equal(t, 5, u.held(1))
}
