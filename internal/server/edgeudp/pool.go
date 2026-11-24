// Package edgeudp manages public UDP ports for tunneled services.
package edgeudp

import (
	"errors"
	"sync"
)

// Pool tracks which ports in [lowPort, highPort] are available.
type Pool struct {
	mu       sync.Mutex
	free     map[int]struct{}
	lowPort  int
	highPort int
}

// NewPool builds a pool covering [low, high] inclusive.
func NewPool(low, high int) *Pool {
	if low < 1 || high > 65535 || low > high {
		panic("edgeudp: invalid port range")
	}
	p := &Pool{
		free:     make(map[int]struct{}, high-low+1),
		lowPort:  low,
		highPort: high,
	}
	for i := low; i <= high; i++ {
		p.free[i] = struct{}{}
	}
	return p
}

// ErrPoolExhausted is returned when no ports remain.
var ErrPoolExhausted = errors.New("edgeudp: no ports available")

// ErrPortUnavailable is returned when a specific port is already allocated.
var ErrPortUnavailable = errors.New("edgeudp: port unavailable")

// ErrPortOutOfRange is returned for ports outside the pool's range.
var ErrPortOutOfRange = errors.New("edgeudp: port out of range")

// Allocate claims a port. If preferred != 0, tries that specific port first.
func (p *Pool) Allocate(preferred int) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if preferred != 0 {
		if preferred < p.lowPort || preferred > p.highPort {
			return 0, ErrPortOutOfRange
		}
		if _, ok := p.free[preferred]; !ok {
			return 0, ErrPortUnavailable
		}
		delete(p.free, preferred)
		return preferred, nil
	}
	for port := range p.free {
		delete(p.free, port)
		return port, nil
	}
	return 0, ErrPoolExhausted
}

// Release returns port to the pool. Ports outside the range are silently
// ignored so callers can Close() listeners unconditionally.
func (p *Pool) Release(port int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if port < p.lowPort || port > p.highPort {
		return
	}
	p.free[port] = struct{}{}
}
