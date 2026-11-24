package testports

import (
	"net"
	"strconv"
	"testing"
)

func TestFreeTCPRangeReturnsBindablePorts(t *testing.T) {
	low, high := FreeTCPRange(t, 5)
	if high-low != 4 {
		t.Fatalf("range %d-%d does not hold 5 ports", low, high)
	}
	if low < lowest || high >= highest {
		t.Fatalf("range %d-%d lies outside %d-%d", low, high, lowest, highest)
	}
	for port := low; port <= high; port++ {
		ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("port %d of the returned range cannot be bound: %v", port, err)
		}
		defer ln.Close()
	}
}

func TestBindableSeesAnOccupiedPort(t *testing.T) {
	low, _ := FreeTCPRange(t, 3)
	ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, strconv.Itoa(low+1)))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if bindable(low, 3) {
		t.Fatalf("range from %d reported free although port %d is taken", low, low+1)
	}
}

func TestFreeUDPRangeReturnsBindablePorts(t *testing.T) {
	low, high := FreeUDPRange(t, 5)
	if high-low != 4 {
		t.Fatalf("range %d-%d does not hold 5 ports", low, high)
	}
	for port := low; port <= high; port++ {
		c, err := net.ListenPacket("udp", net.JoinHostPort(Loopback, strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("port %d of the returned range cannot be bound: %v", port, err)
		}
		defer c.Close()
	}
}

func TestBindableUDPSeesAnOccupiedPort(t *testing.T) {
	low, _ := FreeUDPRange(t, 3)
	c, err := net.ListenPacket("udp", net.JoinHostPort(Loopback, strconv.Itoa(low+1)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if bindableUDP(low, 3) {
		t.Fatalf("range from %d reported free although port %d is taken", low, low+1)
	}
}
