package tests

import (
	"strings"
	"testing"

	"forward/internal/config"
	"forward/internal/dialer"
	"forward/internal/endpoint"

	_ "forward/internal/dialer/http"
	_ "forward/internal/dialer/quic"
	_ "forward/internal/dialer/socks5"
	_ "forward/internal/dialer/vless"
)

func TestForwardChainQuicRequiresUDPBase(t *testing.T) {
	hop1 := *parseEndpoint(t, "http://proxy:8080")
	hop2 := *parseEndpoint(t, "quic://server:443")
	cfg := config.Config{ForwardChain: []endpoint.Endpoint{hop1, hop2}}

	_, err := dialer.New(cfg)
	if err == nil {
		t.Fatal("expected error for quic chain without UDP-capable base")
	}
	if !strings.Contains(err.Error(), "UDP") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestForwardChainQuicWithSocks5(t *testing.T) {
	hop1 := *parseEndpoint(t, "socks5://proxy:1080")
	hop2 := *parseEndpoint(t, "quic://server:443")
	cfg := config.Config{ForwardChain: []endpoint.Endpoint{hop1, hop2}}

	if _, err := dialer.New(cfg); err != nil {
		t.Fatalf("expected quic chain with socks5 base to succeed: %v", err)
	}
}

func TestForwardChainVlessSupported(t *testing.T) {
	hop1 := *parseEndpoint(t, "http://proxy:8080")
	hop2 := *parseEndpoint(t, "vless://11111111-1111-1111-1111-111111111111@server:443?security=tls&sni=example.com")
	cfg := config.Config{ForwardChain: []endpoint.Endpoint{hop1, hop2}}

	if _, err := dialer.New(cfg); err != nil {
		t.Fatalf("expected vless chain to succeed: %v", err)
	}
}
