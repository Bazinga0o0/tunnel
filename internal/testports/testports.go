// Package testports finds free TCP and UDP port ranges for tests.
//
// Fixed port numbers are unreliable: Windows reserves port ranges that change
// with every boot, and a bind inside such a range fails with "access
// permissions". Tests that need a range for a port pool ask for one here.
package testports

import (
	"math/rand/v2"
	"net"
	"strconv"
	"testing"
)

const (
	// Candidates are drawn below the dynamic port range of the common
	// systems, so that outgoing connections of other tests do not take them.
	lowest  = 20000
	highest = 44000

	attempts = 200
)

// Loopback is the address tests bind their listeners to.
const Loopback = "127.0.0.1"

// FreeTCPRange returns the bounds of n consecutive TCP ports that could all be
// bound at the time of the call. The start is random, so test binaries that
// run side by side do not pick the same range.
//
// The probe binds the loopback address only. A port that the system reserves
// is refused on every address, so that is enough, and a listener on all
// interfaces would make the Windows firewall ask for permission on every test
// run.
func FreeTCPRange(t testing.TB, n int) (low, high int) {
	t.Helper()
	if n < 1 || n > highest-lowest {
		t.Fatalf("testports: invalid range size %d", n)
	}
	for range attempts {
		low = lowest + rand.IntN(highest-lowest-n+1)
		if bindable(low, n) {
			return low, low + n - 1
		}
	}
	t.Fatalf("testports: no %d consecutive free TCP ports found", n)
	return 0, 0
}

// FreeUDPRange is FreeTCPRange for UDP ports. The system keeps separate
// reservations for the two protocols, so a range that is free for one need
// not be free for the other.
func FreeUDPRange(t testing.TB, n int) (low, high int) {
	t.Helper()
	if n < 1 || n > highest-lowest {
		t.Fatalf("testports: invalid range size %d", n)
	}
	for range attempts {
		low = lowest + rand.IntN(highest-lowest-n+1)
		if bindableUDP(low, n) {
			return low, low + n - 1
		}
	}
	t.Fatalf("testports: no %d consecutive free UDP ports found", n)
	return 0, 0
}

// bindable reports whether all n ports from low on can be bound at once.
func bindable(low, n int) bool {
	listeners := make([]net.Listener, 0, n)
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()
	for port := low; port < low+n; port++ {
		ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, strconv.Itoa(port)))
		if err != nil {
			return false
		}
		listeners = append(listeners, ln)
	}
	return true
}

// bindableUDP reports whether all n UDP ports from low on can be bound at once.
func bindableUDP(low, n int) bool {
	conns := make([]net.PacketConn, 0, n)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for port := low; port < low+n; port++ {
		c, err := net.ListenPacket("udp", net.JoinHostPort(Loopback, strconv.Itoa(port)))
		if err != nil {
			return false
		}
		conns = append(conns, c)
	}
	return true
}
