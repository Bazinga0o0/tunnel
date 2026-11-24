package edgeguard

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

// drainBufferBytes is the buffer a retired stream is read into. It is small
// on purpose: up to edge.max_conns streams can be draining at a time, and a
// larger buffer only saves calls, not memory, because the stream's receive
// buffer holds what has arrived either way.
const drainBufferBytes = 1 << 10

// maxDrainStalls bounds how often in a row a drain read may return no bytes
// without the stream being gone: a timeout, whose deadline comes from an
// Abort of the edge that lands after Retire (a goroutine of the edge that was
// still on its way out) and is cleared, or a read that returns nothing and no
// error. A yamux stream does neither again once the deadline is cleared; a
// stream whose deadline does not clear would make the drain spin, so after
// this many the drain gives up.
const maxDrainStalls = 3

// drainShrinkInterval is how often at most a paced drain asks its stream to
// give back an empty receive buffer (see drain).
const drainShrinkInterval = time.Second

// draining counts the drain goroutines of Retire that are running.
var draining atomic.Int64

// Draining returns the number of retired streams that are still being
// drained: streams that the edges are done with and that the tunnel client
// keeps open.
func Draining() int {
	return int(draining.Load())
}

// Retire ends an edge's use of a tunnel stream that nobody will read or write
// again: it closes the edge's side and hands the stream to a goroutine that
// reads and discards whatever the tunnel client still sends, until the stream
// is gone from the tunnel session. A yamux stream is gone when the client
// closes or resets its side, when yamux's close timer resets it (five minutes
// after the edge closed it) or when the session ends; then a read returns no
// bytes and io.EOF or yamux.ErrConnectionReset. Then, and only then, the
// goroutine calls release, which may be nil. A read that returned bytes never
// ends the drain, whatever error came with them (see drain).
//
// The edge must call it only once it is completely done with the stream:
// when every goroutine of the edge that reads from or closes the stream has
// returned, every earlier Close (and Abort) included, and none can start one
// afterwards. Until then a half-closed stream still carries the backend's
// answer; and a yamux Close sets the stream's state at once but removes the
// stream from the session only after it has sent its FIN, which can wait up
// to the connection write timeout, so a drain started while another
// goroutine's Close is under way would read EOF and release with the stream
// still in the session. A deadline that lands after Retire (a late Abort's)
// does not end the drain.
//
// While the stream lingers, its receive buffer stays (nearly) empty instead
// of the client filling it up to the stream window and keeping it like that,
// and the buffer is given back whenever it has been read empty (see Shrink).
// The goroutine holds a buffer of drainBufferBytes; it never keeps the
// session alive, because the end of the session ends its read.
func Retire(s Stream, release func(), logger *slog.Logger) {
	draining.Add(1)
	go drain(s, release, logger, nil)
}

// DrainPace is how a paced drain reads a retired stream (see RetirePaced).
type DrainPace struct {
	// Fast is how many bytes the drain first reads at full speed.
	Fast int
	// Burst is the most bytes the slow phase may read at once; it regains
	// Burst bytes per Period.
	Burst  int
	Period time.Duration
}

// DefaultDrainPace is the pace of RetirePaced: two windows (512 KiB) at full
// speed, then half a window (128 KiB) per 30 s, about 4.3 KiB/s.
//
// The rate and the time a slot stays taken after its stream is gone cannot
// both be small (see RetirePaced: their product is at least about half a
// window). The pace favours a low rate, and this is its price:
//
//   - The slow phase throttles an honest client's local service to the
//     drain's rate. An answer with more than about 512 KiB + 300 s ×
//     4.3 KiB/s ≈ 1.8 MiB left when the visitor leaves therefore cannot
//     finish before yamux's close timer: its stream, its place in
//     edge.max_conns and the tunnel owner's stream slot stay taken for five
//     minutes, plus up to GoneWithin(window) ≈ 61 s for what is buffered.
//     That is any answer of a few MiB, not a rare case (at a period of 5 s
//     the threshold was about 8 MiB; with a full-speed drain it was the
//     transfer time).
//   - A stream whose answer ends during the slow phase with a full buffer
//     gives its slot back within GoneWithin(window), about a minute.
//
// What it buys: the rate is what an outsider can turn on at will against an
// honest tunnel. Per lingering stream the client sends at most about 2.0 MiB
// in the five minutes of the close timer (512 KiB + 4.3 KiB/s × 300 s taken
// by the drain, which starts with an empty bucket, plus up to a window left
// in the buffer); for 256 streams about 512 MiB, about 14 Mbit/s of the
// tunnel owner's uplink. At 25.6 KiB/s it was about 8 MiB and 2 GiB
// (55 Mbit/s).
var DefaultDrainPace = DrainPace{
	Fast:   2 * protocol.StreamWindowBytes,
	Burst:  protocol.StreamWindowBytes / 2,
	Period: 30 * time.Second,
}

// GoneWithin returns the longest the slow phase needs to read buffered
// bytes once nothing new arrives: with an empty allowance, buffered bytes at
// Burst per Period, plus one step of waiting.
func (p DrainPace) GoneWithin(buffered int) time.Duration {
	perByte := float64(p.Period) / float64(p.Burst)
	return time.Duration(float64(buffered+drainPacedStep) * perByte)
}

var (
	paceMu sync.Mutex
	pace   = DefaultDrainPace
)

// SetDrainPaceForTesting replaces the pace of RetirePaced and returns the
// function that restores it. For tests only.
func SetDrainPaceForTesting(p DrainPace) (restore func()) {
	paceMu.Lock()
	old := pace
	pace = p
	paceMu.Unlock()
	return func() {
		paceMu.Lock()
		pace = old
		paceMu.Unlock()
	}
}

func currentPace() DrainPace {
	paceMu.Lock()
	defer paceMu.Unlock()
	return pace
}

// drainPacedStep is how much allowance the slow phase waits for before it
// reads again. A read takes at most drainBufferBytes, after which the bucket
// is below the step again, so while the client keeps sending the drain wakes
// about 4.3 times a second at the default pace (1 KiB per wake-up), and up to
// once per frame when the frames are smaller than 1 KiB.
const drainPacedStep = 4 << 10

// RetirePaced is Retire for the HTTP and the TCP edge, whose streams can
// carry a long answer that an honest tunnel client goes on sending after the
// visitor has gone: the client closes its side only when its local service
// closes the connection. A full-speed drain would turn a visitor's aborted
// request into a transfer at line rate, for up to the close timer, against
// the tunnel owner's uplink and the server's ingress. So the drain reads
// DefaultDrainPace.Fast bytes at full speed (enough for what was in flight
// and buffered when the visitor left: an answer that was nearly done ends at
// once), and then at Burst per Period.
//
// While it reads slowly, the stream's buffer may fill to the window (up to
// about twice the window with yamux's buffer growth), which the slot of
// edge.max_conns counts (edgetcp.ConnMemoryBytes). Once the stream is gone
// with a full window buffered, the slot comes back within
// DefaultDrainPace.GoneWithin(window): about a minute; at once when the
// stream's session has ended (SessionDone): nothing more can arrive then,
// and the drain reads the rest at full speed, so that the places on the
// tunnel's name or port, which a new session may take over, are free.
//
// yamux grants the client window only in steps of at least half a window,
// and the drain
// cannot see the client's close until the buffer is empty, so any drain that
// empties a full window within L seconds after a close lets a client that
// does not close send at least half a window per L seconds; this pace keeps
// the product at a window, 4.3 KiB/s against 60 s, and favours the low rate
// (see DefaultDrainPace).
func RetirePaced(s Stream, release func(), logger *slog.Logger) {
	draining.Add(1)
	go drain(s, release, logger, newPacer(currentPace(), SessionDone(s)))
}

// pacer is the allowance of a paced drain: Fast bytes, then a token bucket
// of Burst bytes that refills in Period. A nil *pacer allows everything.
type pacer struct {
	fast   int     // bytes left of the full-speed phase
	burst  float64 // capacity of the bucket
	rate   float64 // bytes per second
	tokens float64
	last   time.Time // of the last refill; zero until the slow phase starts
	// ended is closed when the stream's tunnel session has ended (see
	// SessionDone); nil when the stream cannot tell. From then on nothing
	// more can arrive: what is buffered is bounded, and the drain reads it
	// at full speed, so that the slot's places on the tunnel's name or port,
	// which a new session may take over, come back at once.
	ended <-chan struct{}
}

func newPacer(p DrainPace, ended <-chan struct{}) *pacer {
	return &pacer{fast: p.Fast, burst: float64(p.Burst), rate: float64(p.Burst) / p.Period.Seconds(), ended: ended}
}

// sessionEnded reports whether the stream's tunnel session has ended.
func (p *pacer) sessionEnded() bool {
	select {
	case <-p.ended:
		return true
	default:
		return false
	}
}

// allow returns how many bytes the next read may take, at most limit and at
// least 1 for a limit of at least 1: in the full-speed phase min(limit,
// fast) with fast > 0, in the slow phase max(1, min(limit, tokens)). It
// never returns 0, so the drain never calls Read with an empty slice (which
// a yamux stream with bytes buffered answers with (0, nil), a stall). In
// the slow phase it first sleeps until drainPacedStep bytes (or the whole
// bucket, if smaller) are allowed: at most about a second at the default
// pace, so a stream that is gone is noticed soon after.
func (p *pacer) allow(limit int) int {
	if p == nil {
		return limit
	}
	if p.fast > 0 {
		return min(limit, p.fast)
	}
	if p.sessionEnded() {
		return limit
	}
	step := min(float64(drainPacedStep), p.burst)
	p.refill()
	if p.tokens < step {
		wait := time.NewTimer(time.Duration((step - p.tokens) / p.rate * float64(time.Second)))
		select {
		case <-wait.C:
		case <-p.ended: // a nil channel never fires
			wait.Stop()
			return limit
		}
		p.refill()
	}
	return max(1, min(limit, int(p.tokens)))
}

// took records n bytes read.
func (p *pacer) took(n int) {
	if p == nil {
		return
	}
	if p.fast > 0 {
		p.fast -= min(n, p.fast)
		return
	}
	p.tokens -= float64(n)
}

func (p *pacer) refill() {
	now := time.Now()
	if !p.last.IsZero() {
		p.tokens = min(p.burst, p.tokens+now.Sub(p.last).Seconds()*p.rate)
	}
	p.last = now
}

// drain is the goroutine of Retire. Everything it does with the stream, the
// Close included, runs under its recover, so that a faulty stream cannot keep
// release from being called. release is called in one place, its deferred
// function, after the loop.
//
// What a yamux v0.1.2 stream's Read returns (stream.go Read):
//   - bytes and the error of the window update it sends after taking them
//     from the buffer (sendWindowUpdate; only ErrSessionShutdown is mapped to
//     nil). When the client does not read its connection, that update waits
//     for the connection write timeout and fails with
//     ErrConnectionWriteTimeout, which is not a net.Error. The stream is
//     still there, so the drain goes on; the window was raised before the
//     update was sent, so the next reads do not retry it at once, and every
//     such read takes bytes out of the buffer: no spin.
//   - no bytes and io.EOF once the stream is closed on both sides (the
//     client's FIN, the close timer's forced close, the end of the session)
//     and its buffer is empty; no bytes and ErrConnectionReset after a reset.
//     Each of these is the stream gone from the session.
//   - no bytes and ErrTimeout when a deadline passed: not the end (see
//     maxDrainStalls).
//
// p, when not nil, paces the reads (RetirePaced).
func drain(s Stream, release func(), logger *slog.Logger, p *pacer) {
	defer func() {
		if r := recover(); r != nil && logger != nil {
			LogPanic(logger, r, "tunnel stream drain")
		}
		draining.Add(-1)
		if release != nil {
			release()
		}
	}()
	_ = s.Close()
	_ = s.SetDeadline(time.Time{})
	buf := make([]byte, drainBufferBytes)
	stalls := 0
	defer Shrink(s) // the buffer of a stream that is gone, at once
	lastShrink := time.Now()
	for {
		n, err := s.Read(buf[:p.allow(len(buf))])
		p.took(n)
		// Once the receive buffer has been read empty, the stream gives
		// back its memory instead of keeping it at the largest size a burst
		// made it grow to. Shrink does nothing while bytes are left; a read
		// that returns a full buffer may have emptied it as well. A full-speed
		// drain (a UDP flow's stream, counted at 96 KiB, less than a buffer
		// can hold) asks after every read. A paced drain asks at most once
		// per drainShrinkInterval: once the buffer is gone yamux allocates a
		// new one for every frame, so tiny frames into an emptied stream
		// would cost an allocation each; between two shrinks the buffer holds
		// at most what the window lets in, which the slot of a TCP or HTTP
		// stream counts.
		if p == nil || time.Since(lastShrink) >= drainShrinkInterval {
			Shrink(s)
			lastShrink = time.Now()
		}
		if n > 0 {
			stalls = 0
			continue
		}
		var ne net.Error
		if err == nil || errors.As(err, &ne) && ne.Timeout() {
			if stalls++; stalls > maxDrainStalls {
				return
			}
			_ = s.SetDeadline(time.Time{})
			continue
		}
		return
	}
}
