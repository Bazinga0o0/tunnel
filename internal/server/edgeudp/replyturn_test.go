package edgeudp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// sharedSocket models the UDP socket of a port as its flows share it, the
// way the Go runtime has it: one write deadline for all writers, which
// SetWriteDeadline replaces also for a write that is already waiting, and a
// write lock without any deadline on which writers queue. A write that holds
// the lock takes pace to get its datagram into the send buffer; a negative
// pace is a buffer that never drains.
type sharedSocket struct {
	*fakePacketConn
	pace time.Duration
	// stallAt, when positive, makes the write with that number (counted
	// from 1) take stall and then succeed: its writer is held up while it
	// holds the port's writer slot, as by a collector pause or the scheduler.
	stallAt int32
	stall   time.Duration

	writeMu  sync.Mutex
	mu       sync.Mutex
	deadline time.Time
	sent     atomic.Int32
	writes   atomic.Int32
	// lastSent and longestGap record the longest time between two writes
	// that succeeded: how long the port made no progress at all; stalls are
	// the gaps of at least replyTurnWait.
	lastSent   time.Time
	longestGap time.Duration
	stalls     []stall
}

// stall is a time in which no write succeeded.
type stall struct{ from, to time.Time }

// gap returns the longest time between two successful writes.
func (s *sharedSocket) gap() time.Duration {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.longestGap
}

// excuses reports whether a reply dropped at t is explained by a stall of
// the port: t falls between the start of a stall of at least replyTurnWait
// and its end plus one wait (a waiter that queued during the stall).
func (s *sharedSocket) excuses(t time.Time) bool {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	for _, st := range s.stalls {
		if !t.Before(st.from) && !t.After(st.to.Add(replyTurnWait)) {
			return true
		}
	}
	return false
}

// succeed records a write that succeeded; the caller holds writeMu.
func (s *sharedSocket) succeed() {
	now := time.Now()
	if !s.lastSent.IsZero() {
		gap := now.Sub(s.lastSent)
		s.longestGap = max(s.longestGap, gap)
		if gap >= replyTurnWait {
			s.stalls = append(s.stalls, stall{s.lastSent, now})
		}
	}
	s.lastSent = now
	s.sent.Add(1)
}

func (s *sharedSocket) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadline = t
	return nil
}

func (s *sharedSocket) WriteToUDPAddrPort(b []byte, _ netip.AddrPort) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if n := s.writes.Add(1); s.stallAt > 0 && n == s.stallAt {
		time.Sleep(s.stall)
	}
	start := time.Now()
	for {
		if s.pace >= 0 && time.Since(start) >= s.pace {
			s.succeed()
			return len(b), nil
		}
		s.mu.Lock()
		d := s.deadline
		s.mu.Unlock()
		if !d.IsZero() && !time.Now().Before(d) {
			return 0, os.ErrDeadlineExceeded
		}
		select {
		case <-s.closed:
			return 0, net.ErrClosed
		case <-time.After(200 * time.Microsecond):
		}
	}
}

// replyPort opens a port of mgr on sock and returns the listener.
func replyPort(t *testing.T, mgr *Manager, sock *sharedSocket) (*activeListener, int) {
	t.Helper()
	mgr.listen = func(int) (packetConn, error) { return sock, nil }
	port, err := mgr.Open(context.Background(), 0, newScriptSession())
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Close(port) })
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	return mgr.byPort[port], port
}

// maxReplyBound is the longest a flow's reader may be kept from reading by
// one reply: the wait for the port's writer and one write, with room for a
// loaded machine. It does not grow with the number of flows.
const maxReplyBound = replyTurnWait + replyWriteTimeout + 100*time.Millisecond

// Flows of one port reply one after the
// other, 40 ms apart, into a socket that does not drain. Each reply must
// end within the bound; a later reply must not push out the deadline of a
// write that is already waiting.
func TestALaterReplyDoesNotExtendTheWaitOfAnEarlierOne(t *testing.T) {
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40020, 40020), IdleTimeout: time.Minute, SweepInterval: time.Minute})
	conn, _ := feedSocket(t)
	al, _ := replyPort(t, mgr, &sharedSocket{fakePacketConn: conn, pace: -1})

	const writers = 10
	took := make([]time.Duration, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 40 * time.Millisecond)
			start := time.Now()
			_, _ = al.sendReply([]byte("reply"), netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:4000", i+1)))
			took[i] = time.Since(start)
		}(i)
	}
	wg.Wait()
	for i, d := range took {
		assert.Less(t, d, maxReplyBound, "reply %d kept its reader for %v", i, d)
	}
}

// Many flows of one port reply at once and without pause into a socket that
// does not drain, or drains slowly. No reply keeps its reader longer than
// the bound, however many flows there are.
func TestNoReaderWaitsLongerThanTheBoundWithManyFlows(t *testing.T) {
	for _, tc := range []struct {
		name string
		pace time.Duration
	}{
		{"a socket that does not drain", -1},
		{"a socket that drains slowly", 30 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40021, 40021), IdleTimeout: time.Minute, SweepInterval: time.Minute})
			conn, _ := feedSocket(t)
			al, _ := replyPort(t, mgr, &sharedSocket{fakePacketConn: conn, pace: tc.pace})

			const flows = 64
			var longest atomic.Int64
			var wg sync.WaitGroup
			stop := time.Now().Add(1500 * time.Millisecond)
			for i := 0; i < flows; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					to := netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:4000", i+1))
					for time.Now().Before(stop) {
						start := time.Now()
						_, _ = al.sendReply([]byte("reply"), to)
						d := int64(time.Since(start))
						for {
							cur := longest.Load()
							if d <= cur || longest.CompareAndSwap(cur, d) {
								break
							}
						}
					}
				}(i)
			}
			wg.Wait()
			assert.Less(t, time.Duration(longest.Load()), maxReplyBound,
				"a reader was kept from reading for %v", time.Duration(longest.Load()))
		})
	}
}

// startReplyFlows starts n flows on the port fed by feed and returns the backend
// end of each.
func startReplyFlows(t *testing.T, feed chan<- datagram, sess *scriptSession, n int) []protocol.Stream {
	t.Helper()
	streams := make([]protocol.Stream, n)
	for i := range streams {
		feed <- datagram{[]byte("hello"), netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:4000", i+1))}
		st, _ := acceptFlow(t, sess)
		_, err := protocol.ReadDatagram(st, nil)
		require.NoError(t, err)
		_ = st.(net.Conn).SetDeadline(time.Time{})
		streams[i] = st
	}
	return streams
}

// replyAll has the backend of every flow write replies at once. It returns
// how long that took: the flows' readers took every reply off the streams
// (net.Pipe has no buffer) in that time.
func replyAll(t *testing.T, streams []protocol.Stream, replies int) time.Duration {
	t.Helper()
	start := time.Now()
	errs := make(chan error, len(streams))
	for _, st := range streams {
		go func(st protocol.Stream) {
			for i := 0; i < replies; i++ {
				if err := protocol.WriteDatagram(st, []byte("reply")); err != nil {
					errs <- err
					return
				}
			}
			errs <- nil
		}(st)
	}
	for range streams {
		select {
		case err := <-errs:
			require.NoError(t, err)
		case <-time.After(20 * time.Second):
			t.Fatal("the flows stopped reading their replies")
		}
	}
	return time.Since(start)
}

// With many flows and a socket that does not drain, every flow keeps reading
// its replies and drops them; each is counted.
func TestManyFlowsOnAStuckSocketReadAndDropTheirReplies(t *testing.T) {
	logs := &logCapture{}
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40022, 40022), ReplyCredit: -1,
		IdleTimeout: time.Minute, SweepInterval: time.Minute, Logger: slog.New(logs)})
	conn, feed := feedSocket(t)
	sock := &sharedSocket{fakePacketConn: conn, pace: -1}
	mgr.listen = func(int) (packetConn, error) { return sock, nil }
	sess := newScriptSession()
	port, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(port)

	const flows, replies = 48, 100
	streams := startReplyFlows(t, feed, sess, flows)
	before := requestCount(t, "send_buffer_full")
	took := replyAll(t, streams, replies)
	t.Logf("%d flows got rid of %d replies each in %v", flows, replies, took)
	require.Eventually(t, func() bool { return requestCount(t, "send_buffer_full") == before+flows*replies },
		6*time.Second, 5*time.Millisecond, "every reply was dropped and counted")
	require.Zero(t, sock.sent.Load())
	require.Equal(t, 1, logs.count(slog.LevelWarn, "udp replies dropped"))
}

// healthyReplies has 64 flows of one port reply 50 times each, at once, into
// sock, which takes every write. It returns the times at which replies were
// dropped.
func healthyReplies(t *testing.T, sock *sharedSocket, feed chan<- datagram, port int) []time.Time {
	t.Helper()
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(port, port), ReplyCredit: -1,
		IdleTimeout: time.Minute, SweepInterval: time.Minute})
	mgr.listen = func(int) (packetConn, error) { return sock, nil }
	var mu sync.Mutex
	var drops []time.Time
	mgr.onReplyDrop = func() {
		mu.Lock()
		drops = append(drops, time.Now())
		mu.Unlock()
	}
	sess := newScriptSession()
	p, err := mgr.Open(context.Background(), 0, sess)
	require.NoError(t, err)
	defer mgr.Close(p)

	const flows, replies = 64, 50
	streams := startReplyFlows(t, feed, sess, flows)
	before := requestCount(t, "send_buffer_full")
	replyAll(t, streams, replies)
	require.Eventually(t, func() bool {
		return int(sock.sent.Load())+int(requestCount(t, "send_buffer_full")-before) == flows*replies
	}, 6*time.Second, time.Millisecond, "every reply is sent or dropped")
	mu.Lock()
	defer mu.Unlock()
	return append([]time.Time(nil), drops...)
}

// A socket that is busy but healthy loses nothing when many flows reply at
// once. The writes of all flows of a port take far less than replyTurnWait.
// A drop is allowed only for the one reason the design accepts, and only
// where it applies: the port made no progress at all for at least
// replyTurnWait, because the holder of the writer slot was not running for
// that long (a stall that the holder's own write would not survive on a
// real socket either, see replyTurnWait), and the drop falls between the
// start of that stall and its end plus one wait. A stall elsewhere in the
// run excuses nothing. (A defect that itself freezes the port for a whole
// wait looks like such a stall; the stall test covers the wait.)
func TestManyFlowsOnAHealthySocketLoseNoReply(t *testing.T) {
	conn, feed := feedSocket(t)
	sock := &sharedSocket{fakePacketConn: conn, pace: 0}
	drops := healthyReplies(t, sock, feed, 40023)
	for _, d := range drops {
		require.True(t, sock.excuses(d), "a reply was dropped on a healthy socket outside any stall of a whole turn wait (%d drops)", len(drops))
	}
	if len(drops) > 0 {
		t.Logf("%d replies dropped during a stall; the longest gap was %v", len(drops), sock.gap())
	}
}

// The holder of the writer slot is held up for 20 ms while every other flow
// of the port waits for its turn: a collector pause or a descheduled
// goroutine of an ordinary length on a busy server. The waiters still get
// their turn; a healthy socket loses no reply. (Red with a 10 ms wait.)
// The stall is measured as the longest time without a write: a
// run in which the scheduler stretched it to 30 ms or more is run again,
// up to four times; the fifth such run fails (a defect that itself
// stretches the stall must not pass as a busy machine).
func TestAHolderHeldUpForSomeMillisecondsCostsNoReply(t *testing.T) {
	const stall, ceiling, attempts = 20 * time.Millisecond, 30 * time.Millisecond, 5
	for attempt := 1; ; attempt++ {
		conn, feed := feedSocket(t)
		sock := &sharedSocket{fakePacketConn: conn, pace: 0, stallAt: 200, stall: stall}
		drops := healthyReplies(t, sock, feed, 40027)
		gap := sock.gap()
		require.GreaterOrEqual(t, gap, stall, "the stall happened")
		if gap >= ceiling && attempt < attempts {
			t.Logf("attempt %d: the stall took %v (%d replies dropped); again", attempt, gap, len(drops))
			continue
		}
		require.Less(t, gap, ceiling, "the stall took %v or more in %d attempts", ceiling, attempts)
		require.Empty(t, drops, "replies dropped while the holder was held up for %v", gap)
		return
	}
}

// The warning that a port drops replies is limited for the whole manager,
// not per port: a client that owns many ports cannot multiply it.
func TestTheDropWarningIsLimitedAcrossPorts(t *testing.T) {
	logs := &logCapture{}
	mgr := New(Options{BindHost: "127.0.0.1", Pool: NewPool(40024, 40026), IdleTimeout: time.Minute,
		SweepInterval: time.Minute, Logger: slog.New(logs)})
	for p := 0; p < 3; p++ {
		conn, _ := feedSocket(t)
		al, _ := replyPort(t, mgr, &sharedSocket{fakePacketConn: conn, pace: -1})
		sent, err := al.sendReply([]byte("reply"), netip.MustParseAddrPort("192.0.2.1:4000"))
		require.NoError(t, err)
		require.False(t, sent)
	}
	require.Equal(t, 1, logs.count(slog.LevelWarn, "udp replies dropped"))
}
