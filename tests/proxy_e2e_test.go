package tests

import (
	"net"
	"net/url"
	"testing"
)

func TestProxySchemesTCP(t *testing.T) {
	backendAddr, backendStop := startTCPEchoServer(t)
	defer backendStop()

	cases := []string{
		"http",
		"https",
		"tls",
		"http2",
		"http3",
		"socks5",
		"socks5h",
	}

	for _, scheme := range cases {
		t.Run(scheme, func(t *testing.T) {
			ep, stop := startProxyServer(t, scheme, nil, nil)
			defer stop()

			route := buildRoute(t, ep)
			target := backendAddr
			if scheme == "socks5h" {
				_, port, err := net.SplitHostPort(backendAddr)
				if err != nil {
					t.Fatalf("parse backend addr: %v", err)
				}
				target = net.JoinHostPort("localhost", port)
			}

			conn := dialWithRetry(t, route, "tcp", target)
			defer conn.Close()

			assertEcho(t, conn, []byte("proxy-"+scheme))
		})
	}
}

func TestProxyTransportTunnels(t *testing.T) {
	backendAddr, backendStop := startTCPEchoServer(t)
	defer backendStop()

	cases := []string{
		"socks5+tls",
		"socks5+h2",
		"socks5+h3",
		"socks5+quic",
	}

	for _, scheme := range cases {
		t.Run(scheme, func(t *testing.T) {
			ep, stop := startProxyServer(t, scheme, nil, nil)
			defer stop()

			route := buildRoute(t, ep)
			conn := dialWithRetry(t, route, "tcp", backendAddr)
			defer conn.Close()

			assertEcho(t, conn, []byte("tunnel-"+scheme))
		})
	}
}

func TestProxyTrojan(t *testing.T) {
	backendAddr, backendStop := startTCPEchoServer(t)
	defer backendStop()

	ep, stop := startProxyServer(t, "trojan", url.User("secret"), nil)
	defer stop()

	route := buildRoute(t, ep)
	conn := dialWithRetry(t, route, "tcp", backendAddr)
	defer conn.Close()

	assertEcho(t, conn, []byte("proxy-trojan"))
}
