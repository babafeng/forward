package tproxy

import (
	"net"
	"net/netip"
	"testing"
)

func TestShouldIgnoreUDPSelfTarget(t *testing.T) {
	l := &Listener{
		udpBindPort: 12345,
		localIPs: map[netip.Addr]struct{}{
			netip.MustParseAddr("192.168.1.1"): {},
			netip.MustParseAddr("127.0.0.1"):   {},
		},
	}

	if !l.shouldIgnoreUDP(&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}) {
		t.Fatal("shouldIgnoreUDP = false, want true for self-target listener packet")
	}
	if l.shouldIgnoreUDP(&net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 12345}) {
		t.Fatal("shouldIgnoreUDP = true, want false for remote host on same port")
	}
	if l.shouldIgnoreUDP(&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5353}) {
		t.Fatal("shouldIgnoreUDP = true, want false for local host on different port")
	}
}

func TestNetipAddrFromIPRejectsUnspecified(t *testing.T) {
	if _, ok := netipAddrFromIP(net.IPv4zero); ok {
		t.Fatal("netipAddrFromIP(ok) = true, want false for unspecified IPv4")
	}
	if _, ok := netipAddrFromIP(net.IPv6zero); ok {
		t.Fatal("netipAddrFromIP(ok) = true, want false for unspecified IPv6")
	}
}
