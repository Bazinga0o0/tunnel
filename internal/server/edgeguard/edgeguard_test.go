package edgeguard

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

func TestResolve(t *testing.T) {
	require.Equal(t, 512, Resolve(0, 512), "zero selects the default")
	require.Equal(t, 7, Resolve(7, 512), "a positive value is taken as is")
	require.Equal(t, 0, Resolve(-1, 512), "a negative value disables")

	require.Equal(t, 5*time.Minute, Resolve(0, 5*time.Minute))
	require.Equal(t, time.Second, Resolve(time.Second, 5*time.Minute))
	require.Equal(t, time.Duration(0), Resolve(-time.Second, 5*time.Minute))
}

func TestBackoffDoublesFromMinToMaxAndResets(t *testing.T) {
	var b Backoff
	var got []time.Duration
	for i := 0; i < 10; i++ {
		got = append(got, b.Next())
	}
	require.Equal(t, []time.Duration{
		5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond,
		40 * time.Millisecond, 80 * time.Millisecond, 160 * time.Millisecond,
		320 * time.Millisecond, 640 * time.Millisecond, time.Second, time.Second,
	}, got)

	b.Reset()
	require.Equal(t, 5*time.Millisecond, b.Next(), "after Reset the sequence starts over")
	require.Equal(t, 10*time.Millisecond, b.Next())
}

func TestBackoffSleepWaitsAndHonoursContext(t *testing.T) {
	var b Backoff
	b.Next() // 5 ms
	b.Next() // 10 ms
	b.Next() // 20 ms

	start := time.Now()
	require.True(t, b.Sleep(context.Background()))
	require.GreaterOrEqual(t, time.Since(start), 35*time.Millisecond, "fourth delay is 40 ms")

	for i := 0; i < 10; i++ {
		b.Next() // now at the 1 s ceiling
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	require.False(t, b.Sleep(ctx), "a cancelled context ends the wait")
	require.Less(t, time.Since(start), 800*time.Millisecond)
}

func TestLogLimiterAllowsOnePerInterval(t *testing.T) {
	l := NewLogLimiter(400 * time.Millisecond)

	ok, suppressed := l.Allow()
	require.True(t, ok)
	require.Zero(t, suppressed)

	for i := 0; i < 5; i++ {
		ok, _ = l.Allow()
		require.False(t, ok, "event %d inside the interval is held back", i)
	}

	time.Sleep(500 * time.Millisecond)
	ok, suppressed = l.Allow()
	require.True(t, ok, "the next interval lets one event through again")
	require.Equal(t, 5, suppressed, "and reports how many were held back")

	ok, _ = l.Allow()
	require.False(t, ok)
	time.Sleep(500 * time.Millisecond)
	ok, suppressed = l.Allow()
	require.True(t, ok)
	require.Equal(t, 1, suppressed, "the count starts over after each allowed event")
}

func TestLogLimiterConcurrentUse(t *testing.T) {
	l := NewLogLimiter(time.Minute)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := l.Allow(); ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	require.Equal(t, 1, allowed)
}

func TestRecoverStopsPanicAndLogsIt(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer Recover(logger, "unit test goroutine", "port", 4711)
		var m map[string]int
		m["x"] = 1 // panics: assignment to entry in nil map
	}()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("goroutine did not finish")
	}

	out := buf.String()
	require.Contains(t, out, "level=ERROR")
	require.Contains(t, out, "unit test goroutine")
	require.Contains(t, out, "assignment to entry in nil map")
	require.Contains(t, out, "port=4711")
	require.Contains(t, out, "edgeguard_test.go", "the stack names the panicking frame")
}

func TestRecoverIsSilentWithoutPanic(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	func() {
		defer Recover(logger, "nothing happens")
	}()
	require.Empty(t, buf.String())
}

func TestLimiterEnforcesTotalTunnelAndSource(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	c := netip.MustParseAddr("192.0.2.3")

	t.Run("per source", func(t *testing.T) {
		l := NewLimiter(100, 100, 2)
		_, err := l.Acquire("t1", a)
		require.NoError(t, err)
		rel2, err := l.Acquire("t1", a)
		require.NoError(t, err)
		_, err = l.Acquire("t1", a)
		require.ErrorIs(t, err, ErrLimitSource)

		_, err = l.Acquire("t1", b)
		require.NoError(t, err, "another source has its own budget")
		_, err = l.Acquire("t2", a)
		require.NoError(t, err, "the same source has its own budget on another tunnel")

		rel2()
		_, err = l.Acquire("t1", a)
		require.NoError(t, err, "a released slot can be taken again")
	})

	t.Run("per tunnel", func(t *testing.T) {
		l := NewLimiter(100, 2, 100)
		_, err := l.Acquire("t1", a)
		require.NoError(t, err)
		rel, err := l.Acquire("t1", b)
		require.NoError(t, err)
		_, err = l.Acquire("t1", c)
		require.ErrorIs(t, err, ErrLimitTunnel)
		_, err = l.Acquire("t2", c)
		require.NoError(t, err, "another tunnel has its own budget")
		rel()
		_, err = l.Acquire("t1", c)
		require.NoError(t, err)
	})

	t.Run("total", func(t *testing.T) {
		l := NewLimiter(2, 100, 100)
		rel, err := l.Acquire("t1", a)
		require.NoError(t, err)
		_, err = l.Acquire("t2", b)
		require.NoError(t, err)
		_, err = l.Acquire("t3", c)
		require.ErrorIs(t, err, ErrLimitTotal)
		require.Equal(t, 2, l.Total())
		rel()
		require.Equal(t, 1, l.Total())
		_, err = l.Acquire("t3", c)
		require.NoError(t, err)
	})

	t.Run("a rejected acquire holds nothing", func(t *testing.T) {
		l := NewLimiter(100, 1, 100)
		rel, err := l.Acquire("t1", a)
		require.NoError(t, err)
		for i := 0; i < 5; i++ {
			_, err = l.Acquire("t1", b)
			require.ErrorIs(t, err, ErrLimitTunnel)
		}
		require.Equal(t, 1, l.Total())
		rel()
		require.Zero(t, l.Total())
	})

	t.Run("release is idempotent", func(t *testing.T) {
		l := NewLimiter(100, 100, 100)
		rel1, err := l.Acquire("t1", a)
		require.NoError(t, err)
		_, err = l.Acquire("t1", a)
		require.NoError(t, err)
		rel1()
		rel1()
		rel1()
		require.Equal(t, 1, l.Total(), "releasing one slot three times frees one slot")
	})

	t.Run("limits that are not positive are not enforced", func(t *testing.T) {
		l := NewLimiter(0, 0, 0)
		for i := 0; i < 1000; i++ {
			_, err := l.Acquire("t1", a)
			require.NoError(t, err)
		}
		require.Equal(t, 1000, l.Total())
	})

	t.Run("empty entries are dropped", func(t *testing.T) {
		l := NewLimiter(100, 100, 100)
		var rels []func()
		for _, tun := range []string{"t1", "t2", "t3"} {
			for _, src := range []netip.Addr{a, b, c} {
				rel, err := l.Acquire(tun, src)
				require.NoError(t, err)
				rels = append(rels, rel)
			}
		}
		for _, rel := range rels {
			rel()
		}
		require.Zero(t, l.Total())
		l.mu.Lock()
		defer l.mu.Unlock()
		require.Empty(t, l.tunnels, "no per-tunnel bookkeeping is left behind")
	})
}

func TestLimiterCountsIPv6PerSlash64AndUnmapsIPv4(t *testing.T) {
	l := NewLimiter(100, 100, 1)

	_, err := l.Acquire("t", netip.MustParseAddr("2001:db8:1:2::1"))
	require.NoError(t, err)
	_, err = l.Acquire("t", netip.MustParseAddr("2001:db8:1:2:ffff::9"))
	require.ErrorIs(t, err, ErrLimitSource, "same /64 shares a budget")
	_, err = l.Acquire("t", netip.MustParseAddr("2001:db8:1:3::1"))
	require.NoError(t, err, "another /64 has its own budget")

	_, err = l.Acquire("t", netip.MustParseAddr("198.51.100.7"))
	require.NoError(t, err)
	_, err = l.Acquire("t", netip.MustParseAddr("::ffff:198.51.100.7"))
	require.ErrorIs(t, err, ErrLimitSource, "an IPv4-mapped address is the same source as the IPv4 address")
	_, err = l.Acquire("t", netip.MustParseAddr("198.51.100.8"))
	require.NoError(t, err, "IPv4 is counted per address")
}

func TestSourceKey(t *testing.T) {
	require.Equal(t, netip.MustParseAddr("203.0.113.5"), SourceKey(netip.MustParseAddr("203.0.113.5")))
	require.Equal(t, netip.MustParseAddr("203.0.113.5"), SourceKey(netip.MustParseAddr("::ffff:203.0.113.5")))
	require.Equal(t, netip.MustParseAddr("2001:db8:aa:bb::"), SourceKey(netip.MustParseAddr("2001:db8:aa:bb:1:2:3:4")))
	require.Equal(t, netip.MustParseAddr("fe80::"), SourceKey(netip.MustParseAddr("fe80::1%eth0")), "a zone does not make a new source")
	require.Equal(t, netip.Addr{}, SourceKey(netip.Addr{}))
}

func TestParseSource(t *testing.T) {
	require.Equal(t, netip.MustParseAddr("203.0.113.5"), ParseSource("203.0.113.5:4711"))
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), ParseSource("[2001:db8::1]:443"))
	require.Equal(t, netip.MustParseAddr("203.0.113.5"), ParseSource("[::ffff:203.0.113.5]:443"), "IPv4-mapped is unmapped")
	require.Equal(t, netip.Addr{}, ParseSource("pipe"))
	require.Equal(t, netip.Addr{}, ParseSource(""))
	require.Equal(t, netip.Addr{}, ParseSource("example.com:80"))
}

func TestLimitLabel(t *testing.T) {
	require.Equal(t, "limit_total", LimitLabel(ErrLimitTotal))
	require.Equal(t, "limit_tunnel", LimitLabel(ErrLimitTunnel))
	require.Equal(t, "limit_ip", LimitLabel(ErrLimitSource))
	require.Equal(t, "limit", LimitLabel(io.EOF), "an unknown error still gets a fixed label")
}

// isTimeout reports whether err is a deadline error.
func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func TestIdleClosesBlockedReadAfterTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	idle := NewIdle(200*time.Millisecond, a)
	require.NotNil(t, idle)
	start := time.Now() // before the deadline is set: a pause in between cannot shorten the measured time
	idle.Touch()

	_, err := idle.Reader(a).Read(make([]byte, 1))
	require.Error(t, err)
	require.True(t, isTimeout(err), "got %v", err)
	elapsed := time.Since(start)
	require.GreaterOrEqual(t, elapsed, 150*time.Millisecond)
	require.Less(t, elapsed, 5*time.Second)
}

func TestIdleActivityInEitherDirectionExtendsBothTargets(t *testing.T) {
	// conn stands for the visitor connection, stream for the tunnel stream.
	conn, connPeer := net.Pipe()
	stream, streamPeer := net.Pipe()
	defer conn.Close()
	defer connPeer.Close()
	defer stream.Close()
	defer streamPeer.Close()

	const timeout = time.Second
	idle := NewIdle(timeout, conn, stream)
	idle.Touch()
	start := time.Now()

	// A read on the visitor connection is blocked the whole time.
	readErr := make(chan error, 1)
	go func() {
		_, err := idle.Reader(conn).Read(make([]byte, 1))
		readErr <- err
	}()

	// Activity happens only on the stream, in the write direction, every
	// 100 ms for 2.5 s: two and a half times the timeout.
	go func() { _, _ = io.Copy(io.Discard, streamPeer) }()
	w := idle.Writer(stream)
	var lastWrite time.Time
	for time.Since(start) < 2500*time.Millisecond {
		lastWrite = time.Now() // taken before the write: the deadline is moved after this instant
		_, err := w.Write([]byte("x"))
		require.NoError(t, err)
		select {
		case err := <-readErr:
			t.Fatalf("visitor read ended after %v although the stream was active: %v", time.Since(start), err)
		case <-time.After(100 * time.Millisecond):
		}
	}

	// Once the activity stops the blocked read times out: not earlier than
	// timeout minus one step after the last write, whatever the load.
	select {
	case err := <-readErr:
		require.True(t, isTimeout(err), "got %v", err)
		idleFor := time.Since(lastWrite)
		require.GreaterOrEqual(t, idleFor, timeout-timeout/8-50*time.Millisecond,
			"the deadline may be early by one step, not more")
	case <-time.After(8 * time.Second):
		t.Fatal("visitor read did not time out after the activity stopped")
	}
}

func TestIdleReadActivityExtends(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	idle := NewIdle(800*time.Millisecond, a)
	idle.Touch()
	r := idle.Reader(a)

	go func() {
		for i := 0; i < 20; i++ {
			time.Sleep(100 * time.Millisecond)
			if _, err := b.Write([]byte("y")); err != nil {
				return
			}
		}
	}()

	start := time.Now()
	buf := make([]byte, 1)
	for i := 0; i < 20; i++ {
		_, err := r.Read(buf)
		require.NoError(t, err, "read %d after %v", i, time.Since(start))
	}
	require.GreaterOrEqual(t, time.Since(start), 1900*time.Millisecond, "the connection outlived the timeout because it was active")

	_, err := r.Read(buf)
	require.True(t, isTimeout(err), "got %v", err)
}

func TestIdleDisabled(t *testing.T) {
	require.Nil(t, NewIdle(0), "zero disables")
	require.Nil(t, NewIdle(-time.Second), "negative disables")

	// A nil Idle is usable and passes readers and writers through untouched.
	var idle *Idle
	idle.Touch()
	r := strings.NewReader("abc")
	require.Same(t, r, idle.Reader(r).(*strings.Reader))
	var w bytes.Buffer
	require.Same(t, &w, idle.Writer(&w).(*bytes.Buffer))
}

// bareStream has no deadline methods, like a wrapper that forgot them.
type bareStream struct {
	rwc    io.ReadWriteCloser
	closed *bool
}

func (b bareStream) Read(p []byte) (int, error)  { return b.rwc.Read(p) }
func (b bareStream) Write(p []byte) (int, error) { return b.rwc.Write(p) }
func (b bareStream) Close() error                { *b.closed = true; return b.rwc.Close() }

func TestRequireDeadlines(t *testing.T) {
	// A stream with deadlines is returned as it is.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	st, err := RequireDeadlines(a)
	require.NoError(t, err)
	require.Same(t, a, st)

	// So is a real yamux stream, behind the plain protocol.Stream interface.
	c1, c2 := net.Pipe()
	server, err := protocol.NewServerSession(c1)
	require.NoError(t, err)
	defer server.Close()
	client, err := protocol.NewClientSession(c2)
	require.NoError(t, err)
	defer client.Close()
	raw, err := server.OpenStream()
	require.NoError(t, err)
	st, err = RequireDeadlines(raw)
	require.NoError(t, err)
	require.NoError(t, st.SetDeadline(time.Now().Add(time.Second)))

	// A stream without them is closed and refused.
	c, d := net.Pipe()
	defer d.Close()
	closed := false
	st, err = RequireDeadlines(bareStream{rwc: c, closed: &closed})
	require.ErrorIs(t, err, ErrNoDeadlines)
	require.Nil(t, st)
	require.True(t, closed, "the refused stream is closed, not left to its owner")
	_, err = d.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}

// A yamux stream keeps serving reads after Close until the peer closes too.
// Abort must end a blocked read even when the peer stays silent.
func TestAbortEndsBlockedReadOnYamuxStream(t *testing.T) {
	c1, c2 := net.Pipe()
	server, err := protocol.NewServerSession(c1)
	require.NoError(t, err)
	defer server.Close()
	client, err := protocol.NewClientSession(c2)
	require.NoError(t, err)
	defer client.Close()

	// The peer accepts the stream, reads what arrives and never closes it.
	go func() {
		st, err := client.AcceptStream()
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, st)
	}()

	raw, err := server.OpenStream()
	require.NoError(t, err)
	st, err := RequireDeadlines(raw)
	require.NoError(t, err)
	_, err = st.Write([]byte("hello"))
	require.NoError(t, err)

	readErr := make(chan error, 1)
	go func() {
		_, err := st.Read(make([]byte, 1))
		readErr <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the read block

	Abort(st)
	select {
	case err := <-readErr:
		require.Error(t, err)
	case <-time.After(6 * time.Second):
		t.Fatal("the read on the aborted stream is still blocked")
	}

	_, err = st.Read(make([]byte, 1))
	require.Error(t, err, "later reads fail as well")
	_, err = st.Write([]byte("x"))
	require.Error(t, err, "later writes fail as well")
}

func TestAbortClosesTheStream(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	Abort(a)
	_, err := a.Write([]byte("x"))
	require.ErrorIs(t, err, io.ErrClosedPipe)
	_, err = b.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}

type countingDeadliner struct {
	mu    sync.Mutex
	calls int
	last  time.Time
}

func (c *countingDeadliner) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.last = t
	return nil
}

func (c *countingDeadliner) snapshot() (int, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.last
}

func TestIdleMovesDeadlinesAtMostOncePerStep(t *testing.T) {
	d := &countingDeadliner{}
	idle := NewIdle(4*time.Second, d) // step: 500 ms

	before := time.Now()
	idle.Touch()
	calls, deadline := d.snapshot()
	require.Equal(t, 1, calls, "the first Touch always sets the deadline")
	require.WithinDuration(t, before.Add(4*time.Second), deadline, 400*time.Millisecond)

	for i := 0; i < 1000; i++ {
		idle.Touch()
	}
	calls, _ = d.snapshot()
	require.Equal(t, 1, calls, "touches within one step do not move the deadline again")

	time.Sleep(600 * time.Millisecond)
	before = time.Now()
	idle.Touch()
	calls, deadline = d.snapshot()
	require.Equal(t, 2, calls, "after one step the deadline moves")
	require.WithinDuration(t, before.Add(4*time.Second), deadline, 400*time.Millisecond)
}
