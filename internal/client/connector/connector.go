// Package connector handles incoming data streams from the server and pipes
// them to the locally forwarded port.
package connector

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

const (
	// DefaultDialTimeout bounds the connect to the local service.
	DefaultDialTimeout = 5 * time.Second
	// DefaultMaxStreams is how many streams one Connector serves at a time.
	DefaultMaxStreams = 1024
	// DefaultHeaderTimeout is how long the server may take to send the
	// stream header after it opened a stream.
	DefaultHeaderTimeout = 10 * time.Second
	// DefaultUDPIdleTimeout is how long a UDP flow may stay without a
	// datagram in either direction before the client closes it.
	DefaultUDPIdleTimeout = 5 * time.Minute
)

var (
	// ErrUnexpectedStreamType: the server opened a stream of a type this
	// tunnel was not set up for. A type that is not known at all is refused
	// one step earlier, when the header is read, and Handle then returns an
	// error that wraps protocol.ErrInvalidStreamHeader.
	ErrUnexpectedStreamType = errors.New("unexpected stream type")
	// ErrTooManyStreams: Options.MaxStreams streams are already open.
	ErrTooManyStreams = errors.New("too many concurrent streams")
	// ErrHeaderTimeout: the stream header did not arrive in time.
	ErrHeaderTimeout = errors.New("timed out waiting for the stream header")
	// ErrExpectedTypeNotSet: the Connector was built without
	// Options.ExpectedType and therefore refuses every stream.
	ErrExpectedTypeNotSet = errors.New("connector refuses the stream: Options.ExpectedType is not set")
)

// Options configures a Connector.
//
// Convention for the limits and durations: zero selects the default, a
// negative value switches the limit off.
type Options struct {
	LocalAddr string // e.g. "127.0.0.1:8080"

	// DialTimeout bounds the connect to the local service.
	// Zero: DefaultDialTimeout. Negative: no limit.
	DialTimeout time.Duration

	Logger *slog.Logger

	// ExpectedType is the stream type of the tunnel this Connector serves
	// (http, tcp or udp). Required. A stream of any other type is refused,
	// so that the server cannot make a `tunnel tcp` client send UDP
	// datagrams to the local port or the other way round. There is no
	// default: a Connector built without it refuses every stream with
	// ErrExpectedTypeNotSet. Unknown types are always refused.
	ExpectedType protocol.StreamType

	// MaxStreams limits the streams served at the same time; a stream beyond
	// the limit is closed at once with ErrTooManyStreams.
	// Zero: DefaultMaxStreams. Negative: no limit.
	MaxStreams int

	// HeaderTimeout bounds the wait for the stream header.
	// Zero: DefaultHeaderTimeout. Negative: no limit.
	HeaderTimeout time.Duration

	// UDPIdleTimeout closes a UDP flow that carried no datagram in either
	// direction for this long.
	// Zero: DefaultUDPIdleTimeout. Negative: flows end only with the stream.
	UDPIdleTimeout time.Duration
}

type Connector struct {
	opts   Options
	logger *slog.Logger
	// slots holds one token per stream being served; nil means no limit.
	slots chan struct{}
}

func New(opts Options) *Connector {
	if opts.DialTimeout == 0 {
		opts.DialTimeout = DefaultDialTimeout
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.MaxStreams == 0 {
		opts.MaxStreams = DefaultMaxStreams
	}
	if opts.HeaderTimeout == 0 {
		opts.HeaderTimeout = DefaultHeaderTimeout
	}
	if opts.UDPIdleTimeout == 0 {
		opts.UDPIdleTimeout = DefaultUDPIdleTimeout
	}
	c := &Connector{opts: opts, logger: opts.Logger}
	if opts.MaxStreams > 0 {
		c.slots = make(chan struct{}, opts.MaxStreams)
	}
	return c
}

// Handle serves one stream opened by the server until either side is done.
// The stream is always closed when Handle returns.
func (c *Connector) Handle(stream protocol.Stream) error {
	defer stream.Close()

	// Fail closed: without an expected type there is nothing to check a
	// stream against, so none is served.
	if c.opts.ExpectedType == "" {
		return ErrExpectedTypeNotSet
	}

	if c.slots != nil {
		select {
		case c.slots <- struct{}{}:
			defer func() { <-c.slots }()
		default:
			return ErrTooManyStreams
		}
	}

	hdr, err := c.readHeader(stream)
	if err != nil {
		return err
	}
	if err := c.checkStreamType(hdr.StreamType); err != nil {
		return err
	}
	c.logger.Debug("stream opened", "type", hdr.StreamType, "remote_ip", hdr.RemoteIP, "host", hdr.OriginalHost)

	if hdr.StreamType == protocol.StreamTypeUDP {
		return c.handleUDP(stream, hdr)
	}
	return c.handleTCP(stream, hdr)
}

// readHeader reads the stream header, giving up after HeaderTimeout.
func (c *Connector) readHeader(stream protocol.Stream) (*protocol.StreamHeader, error) {
	var timedOut atomic.Bool
	if c.opts.HeaderTimeout > 0 {
		if rd, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = rd.SetReadDeadline(time.Now().Add(c.opts.HeaderTimeout))
			defer func() { _ = rd.SetReadDeadline(time.Time{}) }()
		} else {
			// No deadline support: closing the stream ends the pending read.
			timer := time.AfterFunc(c.opts.HeaderTimeout, func() {
				timedOut.Store(true)
				_ = stream.Close()
			})
			defer timer.Stop()
		}
	}

	hdr, err := protocol.ReadStreamHeader(stream)
	if err != nil {
		var netErr net.Error
		if timedOut.Load() || (errors.As(err, &netErr) && netErr.Timeout()) {
			return nil, fmt.Errorf("%w (limit %s)", ErrHeaderTimeout, c.opts.HeaderTimeout)
		}
		return nil, fmt.Errorf("read stream header: %w", err)
	}
	return hdr, nil
}

// checkStreamType refuses every stream type but the expected one, and
// unknown types in any case.
//
// protocol.ReadStreamHeader already refuses unknown types, so through Handle
// only the comparison with the expected type can fail today. The rest stays
// as the connector's own line of defence: Handle serves everything that is
// not udp as a TCP stream, so a type that the protocol package came to accept
// one day must not get past this function just because a caller expects it.
func (c *Connector) checkStreamType(got protocol.StreamType) error {
	if want := c.opts.ExpectedType; got != want {
		return fmt.Errorf("%w: got %s, want %s", ErrUnexpectedStreamType, quoteType(got), quoteType(want))
	}
	switch got {
	case protocol.StreamTypeHTTP, protocol.StreamTypeTCP, protocol.StreamTypeUDP:
		return nil
	}
	return fmt.Errorf("%w: got %s", ErrUnexpectedStreamType, quoteType(got))
}

// quoteType renders a stream type from the wire for an error message: cut to
// a short length and quoted, so that it cannot carry control characters.
func quoteType(t protocol.StreamType) string {
	s := string(t)
	if len(s) > 32 {
		s = s[:32]
	}
	return strconv.QuoteToASCII(s)
}

func (c *Connector) handleTCP(stream protocol.Stream, hdr *protocol.StreamHeader) error {
	local, err := net.DialTimeout("tcp", c.opts.LocalAddr, max(c.opts.DialTimeout, 0))
	if err != nil {
		return fmt.Errorf("dial local: %w", err)
	}
	defer local.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, stream)
		if tcp, ok := local.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, local)
		// The local side is done. Close the stream now so that the server
		// learns about it; otherwise the stream would stay open until the
		// public peer goes away.
		//
		// Close on a yamux stream only ends the local writes (it sends FIN).
		// Data from the server keeps arriving and the copy above keeps
		// delivering it to the local service until the server closes its
		// side or yamux's stream close timeout (5 minutes) expires. A local
		// service that half-closes and keeps reading is therefore not cut off.
		_ = stream.Close()
	}()
	wg.Wait()
	return nil
}
