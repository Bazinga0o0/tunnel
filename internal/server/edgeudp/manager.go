package edgeudp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
)

// Defaults of the limits in Options.
const (
	DefaultMaxFlowsPerPort = 256
	DefaultMaxFlowsPerIP   = 64
	// DefaultMaxFlows bounds the flows to 72 MiB at FlowMemoryBytes each
	// (see cmd/tunneld/memory.go for the whole budget); three ports at
	// DefaultMaxFlowsPerPort fill it.
	DefaultMaxFlows       = 768
	DefaultReplyCredit    = 256
	DefaultMaxReplyCredit = 4096

	DefaultMaxQueuedBytesPerFlow = 256 << 10
	DefaultMaxQueuedBytesPerPort = 2 << 20
	DefaultMaxQueuedBytes        = 64 << 20
)

// FlowMemoryBytes is the memory counted for one UDP flow: its two goroutines,
// its queue and its tunnel stream, whose replies the flow keeps reading also
// when it cannot send them, and whose receive buffer it gives back once it
// has read it. Measured (cmd/tunneld/memory_measure_test.go, go1.27.4): 22 KiB
// for an idle flow, 47-54 KiB for a flow whose tunnel client sends replies as
// fast as it can, 77 KiB (heap 70 KiB; with the stacks of its two goroutines
// about 86 KiB) for a flow whose client sent the header of a 64 KiB datagram
// and stops in the middle of it: the flow then holds a scratch buffer of
// 64 KiB while it waits for the rest. Counted at that worst case with
// margin: 96 KiB. The datagrams queued for the tunnel are counted on their
// own (MaxQueuedBytes). A flow whose reader gets no CPU time can still let
// its stream's receive buffer grow to about twice protocol.StreamWindowBytes
// until it catches up. The same holds for a flow whose client sends faster
// than the reader gets rid of replies while the port's socket is stuck or
// slow: the reader waits up to replyTurnWait for each reply's turn.
//
// The stream of a flow that has ended and that the tunnel client keeps open
// keeps the flow's slot of the total until it is gone (edgeguard.Retire):
// measured 23 KiB with a client that keeps writing datagrams as fast as it
// can, against 348 KiB before the drain.
const FlowMemoryBytes = 96 << 10

// ListenerMemoryBytes is the memory counted for one UDP tunnel port: its
// socket, its read loop with a 64 KiB read buffer, and its sweeper. Measured
// (memory_measure_test.go, go1.27.4): a session that holds a UDP port costs
// 128 KiB against 69 KiB for one without, so 59 KiB; counted at 80 KiB.
const ListenerMemoryBytes = 80 << 10

// TunnelOpener mirrors edgetcp's interface — any session that opens yamux streams.
type TunnelOpener interface {
	OpenStream() (protocol.Stream, error)
}

// Options configures a Manager.
type Options struct {
	Pool *Pool
	// IdleTimeout closes a flow that has received no inbound datagram for
	// this long; datagrams sent by the backend do not keep a flow alive.
	// Default 30s.
	IdleTimeout   time.Duration
	BufferSize    int           // per-flow drop-buffer; default 64
	SweepInterval time.Duration // default 5s
	Logger        *slog.Logger

	// BindHost is the local address the tunnel sockets bind to. Empty means
	// all interfaces. Anything else must be an IP address literal such as
	// "127.0.0.1" or "::1"; host names are not resolved, and Open fails for
	// every other value.
	BindHost string

	// The settings below share one convention: zero selects the default, a
	// negative value disables the setting.

	// MaxFlowsPerPort bounds the flows of one tunnel port. Default 256, a third of DefaultMaxFlows.
	MaxFlowsPerPort int
	// MaxFlowsPerIP bounds the flows that one source IP (for IPv6: one /64)
	// holds on one tunnel port. Default 64.
	MaxFlowsPerIP int
	// MaxFlows bounds the flows over all ports of the Manager. Default 768.
	// A flow counts until its tunnel stream is gone, which can be later than
	// the flow (see FlowMemoryBytes); the per-port and per-IP limits count
	// it the same way.
	MaxFlows int
	// ReplyCredit is the number of datagrams the backend may send to a
	// visitor for each datagram received from that visitor. Replies beyond
	// the credit are dropped. Default 256; negative leaves replies unlimited.
	ReplyCredit int
	// MaxReplyCredit caps the credit a flow can accumulate. Default 4096;
	// negative removes the cap.
	MaxReplyCredit int
	// MaxQueuedBytesPerFlow bounds the payload bytes of one flow that wait
	// for the tunnel: datagrams received from the visitor and not yet written
	// to the flow's stream. A datagram that does not fit is dropped. A flow
	// with nothing waiting takes one datagram of any size, so a budget below
	// the datagram size slows a flow down but does not silence it. Default
	// 256 KiB.
	MaxQueuedBytesPerFlow int
	// MaxQueuedBytesPerPort bounds the same over all flows of one tunnel
	// port, so that one tunnel whose client does not take its datagrams
	// cannot use up MaxQueuedBytes and leave nothing for the other tunnels.
	// A port with nothing waiting takes one datagram of any size. Default
	// 2 MiB.
	MaxQueuedBytesPerPort int
	// MaxQueuedBytes bounds the same over all flows and ports of the Manager,
	// with the same exception when nothing at all is waiting. Default 64 MiB.
	MaxQueuedBytes int
}

// Manager opens one UDP socket per allocated port, maintains a flow map
// keyed by (remoteIP, remotePort), and runs a single read loop that demuxes
// datagrams to per-flow goroutine pumps.
type Manager struct {
	opts      Options // resolved: defaults applied, a disabled setting is zero
	creditCap int     // MaxReplyCredit, or math.MaxInt without a cap
	bindErr   error   // set when Options.BindHost is not an IP address
	logger    *slog.Logger
	limiter   *edgeguard.Limiter
	listen    func(port int) (packetConn, error)
	queued    atomic.Int64 // payload bytes waiting for the tunnel, over all flows
	// dropWarn limits the warning that a port drops replies, for all ports
	// together: a tunnel client can make its own port drop at will.
	dropWarn *edgeguard.LogLimiter
	// onReplyDrop, when set (tests), is called for every reply dropped
	// because the port's socket could not take it in time.
	onReplyDrop func()

	mu     sync.Mutex
	byPort map[int]*activeListener
}

// packetConn is the part of *net.UDPConn that the manager uses.
type packetConn interface {
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	Close() error
}

type activeListener struct {
	port     int
	key      string // port as limiter key
	conn     packetConn
	session  TunnelOpener
	cancel   context.CancelFunc
	openWarn *edgeguard.LogLimiter
	readWarn *edgeguard.LogLimiter
	dropWarn *edgeguard.LogLimiter // the Manager's: replies dropped for a full send buffer
	logger   *slog.Logger
	panicLog *edgeguard.LogLimiter // panics of the read loop
	queued   atomic.Int64          // payload bytes waiting for the tunnel, over the flows of this port
	// writer is the port's one writer slot: a reply is written to the socket
	// only by the flow that holds it (see sendReply).
	writer chan struct{}
	// holdReplies is the time (UnixNano) until which replies are dropped
	// without a try, after a write that the socket could not take in time.
	holdReplies atomic.Int64

	mu      sync.Mutex
	closed  bool // set by Close; no flow is added afterwards
	flows   map[netip.AddrPort]*flow
	flowSeq uint64
}

type flow struct {
	id     uint64
	key    netip.AddrPort // source with an IPv4-mapped address unmapped
	addr   netip.AddrPort // source exactly as the socket reported it
	out    chan []byte    // edge -> stream
	closed chan struct{}
	// aborted is closed when the call of close that closed the flow has
	// returned, its Abort of the stream included. A yamux Close sets the
	// stream's state at once but removes the stream from the session only
	// after it has sent its FIN, which can wait up to the connection write
	// timeout; a reader then sees EOF before the stream is gone. So the
	// stream is retired only after this channel is closed.
	aborted chan struct{}
	slot    *edgeguard.Slot // the flow's slot in the limiter
	port    *atomic.Int64   // the listener's count of queued bytes
	total   *atomic.Int64   // the manager's count of queued bytes

	mu       sync.Mutex
	done     bool
	stream   edgeguard.Stream // nil while the stream is being opened
	lastSeen time.Time        // last inbound datagram
	credit   int              // replies the backend may still send
	queued   int              // payload bytes in out or being written to the stream
}

// New creates a Manager with the given options.
func New(opts Options) *Manager {
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 30 * time.Second
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = 64
	}
	if opts.SweepInterval == 0 {
		opts.SweepInterval = 5 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	opts.MaxFlowsPerPort = edgeguard.Resolve(opts.MaxFlowsPerPort, DefaultMaxFlowsPerPort)
	opts.MaxFlowsPerIP = edgeguard.Resolve(opts.MaxFlowsPerIP, DefaultMaxFlowsPerIP)
	opts.MaxFlows = edgeguard.Resolve(opts.MaxFlows, DefaultMaxFlows)
	opts.ReplyCredit = edgeguard.Resolve(opts.ReplyCredit, DefaultReplyCredit)
	opts.MaxReplyCredit = edgeguard.Resolve(opts.MaxReplyCredit, DefaultMaxReplyCredit)
	opts.MaxQueuedBytesPerFlow = edgeguard.Resolve(opts.MaxQueuedBytesPerFlow, DefaultMaxQueuedBytesPerFlow)
	opts.MaxQueuedBytesPerPort = edgeguard.Resolve(opts.MaxQueuedBytesPerPort, DefaultMaxQueuedBytesPerPort)
	opts.MaxQueuedBytes = edgeguard.Resolve(opts.MaxQueuedBytes, DefaultMaxQueuedBytes)

	m := &Manager{
		opts:      opts,
		creditCap: opts.MaxReplyCredit,
		logger:    opts.Logger,
		limiter:   edgeguard.NewLimiter(opts.MaxFlows, opts.MaxFlowsPerPort, opts.MaxFlowsPerIP),
		dropWarn:  edgeguard.NewLogLimiter(edgeguard.LogInterval),
		byPort:    map[int]*activeListener{},
	}
	if m.creditCap == 0 {
		m.creditCap = math.MaxInt
	}
	var bind netip.Addr // the zero Addr is the wildcard address
	if opts.BindHost != "" {
		var err error
		if bind, err = netip.ParseAddr(opts.BindHost); err != nil {
			m.bindErr = fmt.Errorf("edgeudp: BindHost %q is not an IP address", opts.BindHost)
		}
	}
	m.listen = func(port int) (packetConn, error) {
		return net.ListenUDP("udp", listenAddress(bind, port))
	}
	return m
}

// listenAddress returns the address a tunnel socket binds to. The zero Addr
// is the wildcard address.
func listenAddress(bind netip.Addr, port int) *net.UDPAddr {
	if !bind.IsValid() {
		return &net.UDPAddr{Port: port}
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(bind, uint16(port)))
}

// Open allocates a port, opens a UDP listener, and starts the read loop.
func (m *Manager) Open(ctx context.Context, preferred int, session TunnelOpener) (int, error) {
	if m.bindErr != nil {
		return 0, m.bindErr
	}
	port, err := m.opts.Pool.Allocate(preferred)
	if err != nil {
		return 0, err
	}
	conn, err := m.listen(port)
	if err != nil {
		m.opts.Pool.Release(port)
		return 0, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	al := &activeListener{
		port:     port,
		key:      strconv.Itoa(port),
		conn:     conn,
		session:  session,
		cancel:   cancel,
		openWarn: edgeguard.NewLogLimiter(edgeguard.LogInterval),
		readWarn: edgeguard.NewLogLimiter(edgeguard.LogInterval),
		dropWarn: m.dropWarn,
		writer:   make(chan struct{}, 1),
		logger:   m.logger,
		panicLog: edgeguard.NewLogLimiter(edgeguard.LogInterval),
		flows:    map[netip.AddrPort]*flow{},
	}
	m.mu.Lock()
	m.byPort[port] = al
	m.mu.Unlock()
	go m.readLoop(runCtx, al)
	go m.sweepLoop(runCtx, al)
	m.logger.Info("udp tunnel listener opened", "port", port)
	return port, nil
}

// Close stops the listener and tears down all flows.
func (m *Manager) Close(port int) {
	m.mu.Lock()
	al, ok := m.byPort[port]
	if ok {
		delete(m.byPort, port)
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	al.cancel()
	_ = al.conn.Close()

	// The map is emptied, never set to nil: a datagram that is already past
	// the socket read sees the closed flag under the same lock and is dropped.
	al.mu.Lock()
	al.closed = true
	flows := make([]*flow, 0, len(al.flows))
	for _, f := range al.flows {
		flows = append(flows, f)
	}
	clear(al.flows)
	al.mu.Unlock()
	for _, f := range flows {
		f.close()
	}

	m.opts.Pool.Release(port)
	m.logger.Info("udp tunnel listener closed", "port", port)
}

// readLoop reads datagrams until the socket is closed. A panic at loop level
// does not end it: the port would stay bound with nobody reading from it.
// The loop is entered again instead, after the pause of the backoff, so that
// a panic that repeats does not spin.
func (m *Manager) readLoop(ctx context.Context, al *activeListener) {
	buf := make([]byte, 65536)
	var backoff edgeguard.Backoff
	for m.readDatagrams(ctx, al, buf, &backoff) {
		if !backoff.Sleep(ctx) {
			return
		}
	}
}

// readDatagrams is the read loop proper. It returns true when a panic ended
// it and false when the socket was closed.
//
// The panic is logged with its stack through a limiter: a successful read
// resets the backoff, so panics that alternate with successes could otherwise
// write a stack every few milliseconds.
func (m *Manager) readDatagrams(ctx context.Context, al *activeListener, buf []byte, backoff *edgeguard.Backoff) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			if ok, suppressed := al.panicLog.Allow(); ok {
				edgeguard.LogPanic(m.logger, r, "udp read loop", "port", al.port, "suppressed", suppressed)
			}
			panicked = true
		}
	}()
	for {
		n, src, err := al.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			if ok, suppressed := al.readWarn.Allow(); ok {
				m.logger.Warn("udp read failed", "port", al.port, "err", err, "suppressed", suppressed)
			}
			if !backoff.Sleep(ctx) {
				return
			}
			continue
		}
		backoff.Reset()
		m.dispatch(al, src, buf[:n])
	}
}

// dispatch hands one inbound datagram to its flow and starts the flow when
// the datagram is the first from its source. It never waits for the tunnel:
// the stream of a new flow is opened by the flow's own goroutine, and a flow
// that cannot keep up loses datagrams instead of stalling the port.
func (m *Manager) dispatch(al *activeListener, src netip.AddrPort, data []byte) {
	// A panic costs this datagram, not the read loop.
	defer edgeguard.Recover(m.logger, "udp datagram", "port", al.port)

	f, isNew, err := m.lookupOrCreateFlow(al, src)
	if err != nil {
		metrics.RequestTotal.WithLabelValues("udp", edgeguard.LimitLabel(err)).Inc()
		return
	}
	if f == nil {
		return // listener closed
	}
	if isNew {
		go m.runFlow(al, f)
	}
	// Copy bytes before they're overwritten by the next read.
	payload := append([]byte(nil), data...)
	if status := m.offer(f, payload); status != "" {
		metrics.RequestTotal.WithLabelValues("udp", status).Inc()
	}
}

// offer queues one inbound datagram for the flow's stream. It returns "" when
// the datagram was queued and otherwise the metric status under which it is
// dropped: "limit_buffer" when it does not fit into the byte budget of the
// flow, of the port or of the manager, "drop" when the flow's buffer is full
// or the flow has ended.
//
// A datagram counts against the byte budgets from here until the pump has
// written it to the stream. At each of the three levels, nothing queued means
// that one datagram of any size is taken.
func (m *Manager) offer(f *flow, payload []byte) string {
	n := len(payload)

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done {
		return "drop"
	}
	if max := m.opts.MaxQueuedBytesPerFlow; max > 0 && f.queued > 0 && f.queued+n > max {
		return "limit_buffer"
	}
	// The port before the manager: a port that is full must not take from
	// the budget that all ports share.
	if !reserve(f.port, m.opts.MaxQueuedBytesPerPort, n) {
		return "limit_buffer"
	}
	if !reserve(f.total, m.opts.MaxQueuedBytes, n) {
		f.port.Add(-int64(n))
		return "limit_buffer"
	}

	// The credit for the replies is granted before the datagram can reach
	// the backend, and taken back if it does not get there: granted after
	// the send, the reply of a fast backend would meet a flow without credit.
	credit := f.credit
	if grant := m.opts.ReplyCredit; f.credit > m.creditCap-grant {
		f.credit = m.creditCap
	} else {
		f.credit += grant
	}
	select {
	case f.out <- payload:
		f.queued += n
		f.lastSeen = time.Now() // only a queued datagram refreshes the idle timer
		return ""
	default:
		f.credit = credit
		f.port.Add(-int64(n))
		f.total.Add(-int64(n))
		return "drop"
	}
}

// reserve books n bytes in a byte budget of max bytes, of which queued are
// taken. It reports false when they do not fit. A budget that is not positive
// is not enforced, and one with nothing taken accepts any n.
func reserve(queued *atomic.Int64, max, n int) bool {
	for {
		cur := queued.Load()
		if max > 0 && cur > 0 && cur+int64(n) > int64(max) {
			return false
		}
		if queued.CompareAndSwap(cur, cur+int64(n)) {
			return true
		}
	}
}

// lookupOrCreateFlow returns the flow for src. A new flow is entered into
// the map before its stream exists, under the listener's lock and only while
// the listener is open and the limits allow it. It returns a nil flow when
// the listener is closed and an edgeguard.ErrLimit error when a limit is hit.
func (m *Manager) lookupOrCreateFlow(al *activeListener, src netip.AddrPort) (f *flow, isNew bool, err error) {
	key := netip.AddrPortFrom(src.Addr().Unmap(), src.Port())

	al.mu.Lock()
	defer al.mu.Unlock()
	if al.closed {
		return nil, false, nil
	}
	if f, ok := al.flows[key]; ok {
		return f, false, nil
	}
	slot, err := m.limiter.Take(al.key, key.Addr())
	if err != nil {
		return nil, false, err
	}
	al.flowSeq++
	f = &flow{
		id:       al.flowSeq,
		key:      key,
		addr:     src,
		out:      make(chan []byte, m.opts.BufferSize),
		closed:   make(chan struct{}),
		aborted:  make(chan struct{}),
		slot:     slot,
		port:     &al.queued,
		total:    &m.queued,
		lastSeen: time.Now(),
	}
	al.flows[key] = f
	return f, true, nil
}

// runFlow opens the stream of a new flow and then pumps the flow's inbound
// datagrams into it. The flow is gone when runFlow returns.
//
// The stream holds the flow's place in the total from before it is opened
// until it is gone from the session: the flow's last reader of the stream
// retires it (see edgeguard.Retire), which is streamRead once it runs and
// runFlow before. Eviction and retirement are separate deferred calls, the
// retirement registered first so that it runs last: a panic in the eviction
// (closing the stream) does not skip it.
func (m *Manager) runFlow(al *activeListener, f *flow) {
	defer edgeguard.Recover(m.logger, "udp flow", "port", al.port, "flow_id", f.id)
	reason := "panic"
	var stream edgeguard.Stream // set once opened
	retire := true              // false once streamRead owns the stream
	streamDone, ok := f.slot.Hold()
	defer func() {
		switch {
		case stream == nil:
			streamDone()
		case retire:
			<-f.aborted // every Close of the stream has returned (see flow.aborted)
			edgeguard.Retire(stream, streamDone, m.logger)
		}
	}()
	defer func() { m.evictFlow(al, f, reason) }()
	if !ok {
		reason = "closed before the stream was opened"
		return
	}

	raw, err := al.session.OpenStream()
	if err != nil {
		if ok, suppressed := al.openWarn.Allow(); ok {
			m.logger.Warn("udp open stream failed", "port", al.port, "err", err, "suppressed", suppressed)
		}
		reason = "open stream failed"
		return
	}
	// Ending a flow needs a stream that takes deadlines. One that does not
	// is refused instead of being used without them.
	st, err := edgeguard.RequireDeadlines(raw)
	if err != nil {
		metrics.RequestTotal.WithLabelValues("udp", "stream_rejected").Inc()
		if ok, suppressed := al.openWarn.Allow(); ok {
			m.logger.Warn("udp tunnel stream refused", "port", al.port, "err", err, "suppressed", suppressed)
		}
		reason = "stream without deadlines"
		return
	}
	stream = st
	// The listener may have been closed, or the flow evicted, while the
	// stream was being opened. Then the fresh stream is retired instead of
	// being put to use.
	if !f.attach(stream) {
		reason = "closed while the stream was opened"
		return
	}
	hdr := &protocol.StreamHeader{
		StreamType: protocol.StreamTypeUDP,
		RemoteIP:   f.key.Addr().String(),
		RemotePort: int(f.key.Port()),
		PublicPort: al.port,
		FlowID:     f.id,
	}
	if err := protocol.WriteStreamHeader(stream, hdr); err != nil {
		reason = "stream header write failed"
		return
	}
	metrics.RequestTotal.WithLabelValues("udp", "flow_open").Inc()

	retire = false
	go m.streamRead(f, al, stream, streamDone)
	reason = m.streamPump(f, stream)
}

// streamPump writes the flow's inbound datagrams to the stream until the
// flow is closed. It returns the reason for the end.
func (m *Manager) streamPump(f *flow, stream edgeguard.Stream) string {
	for {
		select {
		case <-f.closed:
			return "flow closed"
		case payload := <-f.out:
			err := protocol.WriteDatagram(stream, payload)
			f.written(len(payload))
			if err != nil {
				return "stream write failed"
			}
		}
	}
}

// scratchPool holds the buffers that replies are read into. A flow borrows
// one only while a reply is in transit, so idle flows hold no buffer.
var scratchPool = sync.Pool{
	New: func() any {
		b := make([]byte, protocol.MaxDatagramSize)
		return &b
	},
}

// streamRead sends the backend's replies to the visitor. It is the only
// reader of the stream: when it ends, the flow is closed and nothing reads
// the stream again, so it retires the stream, which gives back streamDone
// when the stream is gone. The retirement is deferred before the eviction,
// so that it runs after it, also when the eviction panics.
func (m *Manager) streamRead(f *flow, al *activeListener, stream edgeguard.Stream, streamDone func()) {
	defer edgeguard.Recover(m.logger, "udp flow reader", "port", al.port, "flow_id", f.id)
	reason := "panic"
	defer func() {
		<-f.aborted // every Close of the stream has returned (see flow.aborted)
		edgeguard.Retire(stream, streamDone, m.logger)
	}()
	defer func() { m.evictFlow(al, f, reason) }()

	// The small reader only serves to wait for the first byte of a reply
	// before a scratch buffer is taken from the pool.
	br := bufio.NewReaderSize(stream, 16)
	for {
		if _, err := br.Peek(1); err != nil {
			reason = "stream read failed"
			return
		}
		if reason = m.forwardReply(f, al, br); reason != "" {
			return
		}
		// A burst of replies makes the stream's receive buffer grow; once
		// everything is read the stream gives that memory back, instead of
		// keeping it for as long as the flow lives.
		if br.Buffered() == 0 {
			edgeguard.Shrink(stream)
		}
	}
}

// The flows of a port share its socket, and with it one write deadline and
// the socket's write lock, on which writers queue without any deadline. So
// a reply is written only by the flow that holds the port's one writer slot:
// a flow's reader waits at most replyTurnWait for the slot and drops its
// reply when it does not get it; the holder sets the deadline for its own
// write, which no other write can move, and waits at most replyWriteTimeout
// for room in the socket's send buffer. After a write that ran out of that
// time, replies are dropped without a try for replyHold. A reader is kept
// from reading by one reply for at most replyTurnWait + replyWriteTimeout,
// however many flows the port has: the flows keep reading their streams, so
// a socket that cannot send makes the server drop replies, not pile up what
// the clients keep sending.
//
// replyWriteTimeout is long enough that a healthy socket never trips it: a
// socket whose buffer drains at all has room again within milliseconds, a
// write on a host with limited egress or a busy CPU waits ten or twenty, and
// the goroutine being descheduled between setting the deadline and writing
// (which fails the write without a try once the deadline has passed) takes
// a stall of that length.
//
// replyTurnWait is as long as replyWriteTimeout, for the same reason. The
// writes of all flows of a busy port before a waiter take microseconds
// each. But while the holder of the slot is not running (a collector
// pause, a goroutine or thread descheduled on a busy host), no waiter gets
// its turn, and when the wait runs out every waiter of the port drops a
// reply at the same moment. With the wait as long as the write's own limit,
// a stall that the holder's write survives on a real socket costs no reply.
// A wait of 10 ms did not: the tests measured stalls of 8 to 23 ms on
// a busy machine, and a healthy port lost a reply on every flow.
//
// The bound is 100 ms per reply: a wait that ends with the slot, then a
// write that runs out of its time. It is reached only when a socket becomes
// stuck. While a socket stays stuck, a waiter waits at most replyTurnWait,
// and the hold that follows a timed-out write makes every reader drop at
// once. While a reader waits, its tunnel client can fill the stream's
// receive window, as with the shorter wait (see FlowMemoryBytes).
//
// replyHold is short, so that a trip costs little, and long enough that the
// readers of a port whose socket stays full spend a fair part of the time
// reading and dropping, which empties what came in while they waited.
const (
	replyWriteTimeout = 50 * time.Millisecond
	replyTurnWait     = replyWriteTimeout
	replyHold         = 20 * time.Millisecond
)

// writeDeadliner is the part of *net.UDPConn that bounds a write.
type writeDeadliner interface {
	SetWriteDeadline(time.Time) error
}

// sendReply writes one reply to the visitor. It reports false when the reply
// was dropped because the port's socket could not take it in time (the
// writer slot was busy for replyTurnWait, the write ran out of
// replyWriteTimeout, or the port holds its replies after such a write), and
// returns an error for any other failure of the write.
func (al *activeListener) sendReply(payload []byte, to netip.AddrPort) (sent bool, err error) {
	if time.Now().UnixNano() < al.holdReplies.Load() {
		return false, nil
	}
	if !al.takeWriter() {
		return false, nil
	}
	defer func() { <-al.writer }()
	now := time.Now()
	if now.UnixNano() < al.holdReplies.Load() { // a write timed out while this one waited
		return false, nil
	}
	if d, ok := al.conn.(writeDeadliner); ok {
		_ = d.SetWriteDeadline(now.Add(replyWriteTimeout))
	}
	if _, err := al.conn.WriteToUDPAddrPort(payload, to); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			al.holdReplies.Store(time.Now().Add(replyHold).UnixNano())
			if ok, suppressed := al.dropWarn.Allow(); ok {
				al.logger.Warn("udp replies dropped: the socket's send buffer stays full", "port", al.port,
					"hold", replyHold, "suppressed", suppressed)
			}
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// takeWriter takes the port's writer slot, waiting for it at most
// replyTurnWait. It reports whether it got it; the caller gives it back.
func (al *activeListener) takeWriter() bool {
	select {
	case al.writer <- struct{}{}:
		return true
	default:
	}
	t := time.NewTimer(replyTurnWait)
	defer t.Stop()
	select {
	case al.writer <- struct{}{}:
		return true
	case <-t.C:
		return false
	}
}

// forwardReply reads one reply from r and sends it to the visitor if the
// flow has credit for it. It returns the reason when the flow has to end.
func (m *Manager) forwardReply(f *flow, al *activeListener, r io.Reader) string {
	bp := scratchPool.Get().(*[]byte)
	defer scratchPool.Put(bp)

	payload, err := protocol.ReadDatagram(r, *bp)
	if err != nil {
		return "stream read failed"
	}
	if payload == nil {
		return ""
	}
	if m.opts.ReplyCredit > 0 && !f.spend() {
		metrics.RequestTotal.WithLabelValues("udp", "reply_limit").Inc()
		return ""
	}
	sent, err := al.sendReply(payload, f.addr)
	if err != nil {
		return "udp write failed"
	}
	if !sent {
		metrics.RequestTotal.WithLabelValues("udp", "send_buffer_full").Inc()
		if m.onReplyDrop != nil {
			m.onReplyDrop()
		}
	}
	return ""
}

func (m *Manager) sweepLoop(ctx context.Context, al *activeListener) {
	t := time.NewTicker(m.opts.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.sweep(al)
		}
	}
}

// sweep evicts the flows that have been idle for longer than the timeout.
func (m *Manager) sweep(al *activeListener) {
	// A panic costs this round, not the sweeper.
	defer edgeguard.Recover(m.logger, "udp sweep", "port", al.port)

	cutoff := time.Now().Add(-m.opts.IdleTimeout)
	var idle []*flow
	al.mu.Lock()
	for _, f := range al.flows {
		if f.idleSince(cutoff) {
			idle = append(idle, f)
		}
	}
	al.mu.Unlock()
	for _, f := range idle {
		m.evictFlow(al, f, "idle timeout")
	}
}

func (m *Manager) evictFlow(al *activeListener, f *flow, reason string) {
	al.mu.Lock()
	if cur, ok := al.flows[f.key]; ok && cur == f {
		delete(al.flows, f.key)
	}
	al.mu.Unlock()
	if f.close() {
		m.logger.Debug("udp flow closed", "port", al.port, "flow_id", f.id, "reason", reason)
	}
}

// attach hands the opened stream to the flow. It returns false when the flow
// was closed in the meantime; the caller then owns the stream.
func (f *flow) attach(stream edgeguard.Stream) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done {
		return false
	}
	f.stream = stream
	return true
}

// close ends the flow: it stops the pumps, gives back the flow's slot and
// aborts the stream if there is one, which ends the reader's read; the stream
// keeps its place in the total until it is gone (see runFlow). It reports
// whether this call did the closing.
func (f *flow) close() bool {
	f.mu.Lock()
	if f.done {
		f.mu.Unlock()
		return false
	}
	f.done = true
	stream := f.stream
	queued := f.queued
	f.queued = 0
	f.mu.Unlock()
	defer close(f.aborted) // also when closing the stream panics

	// What was still waiting is not going to be written.
	f.port.Add(-int64(queued))
	f.total.Add(-int64(queued))
	close(f.closed)
	f.slot.Release() // before the stream is touched: the slot must not depend on it
	if stream != nil {
		edgeguard.Abort(stream)
	}
	return true
}

// written takes a datagram of n bytes that the pump is done with out of the
// byte budgets. A flow that has ended has given everything back already.
func (f *flow) written(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done {
		return
	}
	f.queued -= n
	f.port.Add(-int64(n))
	f.total.Add(-int64(n))
}

// spend takes one reply out of the flow's credit.
func (f *flow) spend() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.credit <= 0 {
		return false
	}
	f.credit--
	return true
}

func (f *flow) idleSince(cutoff time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastSeen.Before(cutoff)
}
