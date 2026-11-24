package connector

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/protocol"
)

func (c *Connector) handleUDP(stream protocol.Stream, hdr *protocol.StreamHeader) error {
	udpAddr, err := net.ResolveUDPAddr("udp", c.opts.LocalAddr)
	if err != nil {
		return fmt.Errorf("resolve local udp: %w", err)
	}
	local, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("dial local udp: %w", err)
	}
	defer local.Close()

	c.logger.Debug("udp flow opened", "flow_id", hdr.FlowID, "remote", hdr.RemoteIP)

	// Without this the flow would only end when the server closes the
	// stream: a flow nobody uses any more would keep its socket, two
	// goroutines and a stream slot for as long as the session lives.
	idle := newIdleWatch(c.opts.UDPIdleTimeout, func() {
		c.logger.Debug("udp flow idle, closing", "flow_id", hdr.FlowID)
		_ = stream.Close()
		_ = local.Close()
	})
	defer idle.stop()

	var wg sync.WaitGroup
	wg.Add(2)

	// stream -> local
	go func() {
		defer wg.Done()
		scratch := make([]byte, 65536)
		for {
			payload, err := protocol.ReadDatagram(stream, scratch)
			if err != nil {
				_ = local.Close()
				return
			}
			idle.touch()
			if payload == nil {
				continue
			}
			if _, err := local.Write(payload); err != nil {
				_ = local.Close()
				return
			}
		}
	}()

	// local -> stream
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, _, err := local.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				_ = stream.Close()
				return
			}
			idle.touch()
			if err := protocol.WriteDatagram(stream, buf[:n]); err != nil {
				_ = stream.Close()
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

// idleWatch calls onIdle once when touch has not been called for timeout.
// A nil *idleWatch is valid and does nothing (timeout switched off).
type idleWatch struct {
	timeout time.Duration
	onIdle  func()
	start   time.Time
	// last is the time of the latest activity as an offset from start
	// (monotonic clock, so wall-clock jumps do not matter).
	last atomic.Int64

	mu      sync.Mutex
	timer   *time.Timer
	stopped bool
}

func newIdleWatch(timeout time.Duration, onIdle func()) *idleWatch {
	if timeout <= 0 {
		return nil
	}
	w := &idleWatch{timeout: timeout, onIdle: onIdle, start: time.Now()}
	w.mu.Lock()
	w.timer = time.AfterFunc(timeout, w.check)
	w.mu.Unlock()
	return w
}

// touch records activity. It is called once per datagram, so it only stores
// a timestamp; the timer re-arms itself in check.
func (w *idleWatch) touch() {
	if w == nil {
		return
	}
	w.last.Store(int64(time.Since(w.start)))
}

func (w *idleWatch) check() {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	idleFor := time.Since(w.start) - time.Duration(w.last.Load())
	if idleFor < w.timeout {
		w.timer.Reset(w.timeout - idleFor)
		w.mu.Unlock()
		return
	}
	w.stopped = true
	w.mu.Unlock()
	w.onIdle()
}

func (w *idleWatch) stop() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.stopped = true
	w.timer.Stop()
	w.mu.Unlock()
}
