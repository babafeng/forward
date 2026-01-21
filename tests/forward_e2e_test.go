package tests

import (
	"net"
	"testing"
)

func TestPortForwardTransports(t *testing.T) {
	backendAddr, backendStop := startTCPEchoServer(t)
	defer backendStop()

	cases := []string{
		"tcp",
		"tcp+tls",
		"tcp+dtls",
		"tcp+h2",
		"tcp+h3",
		"quic",
	}

	for _, scheme := range cases {
		t.Run(scheme, func(t *testing.T) {
			ep, stop := startPortForwardServer(t, scheme, backendAddr)
			defer stop()

			route := buildRoute(t, ep)
			conn := dialWithRetry(t, route, "tcp", backendAddr)
			defer conn.Close()

			assertEcho(t, conn, []byte("ping-"+scheme))
		})
	}
}

func TestUDPPortForward(t *testing.T) {
	backendAddr, backendStop := startUDPEchoServer(t)
	defer backendStop()

	ep, stop := startPortForwardServer(t, "udp", backendAddr)
	defer stop()

	conn, err := net.Dial("udp", ep.Address())
	if err != nil {
		t.Fatalf("dial udp forward: %v", err)
	}
	defer conn.Close()

	assertUDPEcho(t, conn, []byte("udp-ping"))
}
