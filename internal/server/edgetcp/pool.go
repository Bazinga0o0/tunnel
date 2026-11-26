// Package edgetcp manages public TCP ports for tunneled services.
package edgetcp

import (
	"errors"
	"sync"
)

// Pool tracks which ports in [lowPort, highPort] are available.
type Pool struct {
	mu       sync.Mutex
	free     map[int]struct{}
	excluded map[int]struct{} // never drawn at random (Exclude)
	lowPort  int
	highPort int
}

// NewPool builds a pool covering [low, high] inclusive.
func NewPool(low, high int) *Pool {
	if low < 1 || high > 65535 || low > high {
		panic("edgetcp: invalid port range")
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
var ErrPoolExhausted = errors.New("edgetcp: no ports available")

// ErrPortUnavailable is returned when a specific port is already allocated.
var ErrPortUnavailable = errors.New("edgetcp: port unavailable")

// ErrPortOutOfRange is returned for ports outside the pool's range.
var ErrPortOutOfRange = errors.New("edgetcp: port out of range")

// Exclude keeps ports out of the random draw of Allocate(0); asked for by
// number they are allocated as any other port. The ports of the registered
// services are excluded: between two holders such a port is free, and it
// must not fall to the tunnel of an account that asked for any port. Ports
// outside the range are ignored. Call it before the pool is in use.
func (p *Pool) Exclude(ports []int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, port := range ports {
		if port < p.lowPort || port > p.highPort {
			continue
		}
		if p.excluded == nil {
			p.excluded = map[int]struct{}{}
		}
		p.excluded[port] = struct{}{}
	}
}

// SetExcluded replaces the set of ports Exclude built, for a reload of the
// config while the pool is in use. A port that was excluded and no longer is
// is drawn at random again; a port that is allocated stays allocated either
// way. Ports outside the range are ignored.
func (p *Pool) SetExcluded(ports []int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.excluded = nil
	for _, port := range ports {
		if port < p.lowPort || port > p.highPort {
			continue
		}
		if p.excluded == nil {
			p.excluded = map[int]struct{}{}
		}
		p.excluded[port] = struct{}{}
	}
}

// Allocate claims a port. If preferred != 0, tries that specific port first;
// otherwise it draws a free port that is not excluded (see Exclude).
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
		if _, ok := p.excluded[port]; ok {
			continue
		}
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
