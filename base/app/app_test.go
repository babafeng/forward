package app

import (
	"testing"

	"forward/base/endpoint"
	"forward/internal/config"
)

func TestSplitSchemeTransport(t *testing.T) {
	tests := []struct {
		scheme        string
		wantBase      string
		wantTransport transportKind
	}{
		{scheme: "http2", wantBase: "http2", wantTransport: transportNone},
		{scheme: "http3", wantBase: "http3", wantTransport: transportNone},
		{scheme: "tls", wantBase: "http", wantTransport: transportTLS},
		{scheme: "h2", wantBase: "http", wantTransport: transportH2},
		{scheme: "h3", wantBase: "http", wantTransport: transportH3},
		{scheme: "socks5+h2", wantBase: "socks5", wantTransport: transportH2},
		{scheme: "socks5+h3", wantBase: "socks5", wantTransport: transportH3},
	}

	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			base, transport := splitSchemeTransport(tt.scheme)
			if base != tt.wantBase {
				t.Fatalf("base = %q, want %q", base, tt.wantBase)
			}
			if transport != tt.wantTransport {
				t.Fatalf("transport = %q, want %q", transport, tt.wantTransport)
			}
		})
	}
}

func TestNormalizeProxySchemesHTTP2(t *testing.T) {
	handlerScheme, listenerScheme, transport := normalizeProxySchemes("http2")
	if handlerScheme != "http" {
		t.Fatalf("handler = %q, want %q", handlerScheme, "http")
	}
	if listenerScheme != "http2" {
		t.Fatalf("listener = %q, want %q", listenerScheme, "http2")
	}
	if transport != transportNone {
		t.Fatalf("transport = %q, want %q", transport, transportNone)
	}
}

func TestNormalizeProxySchemesH3Transport(t *testing.T) {
	handlerScheme, listenerScheme, transport := normalizeProxySchemes("socks5+h3")
	if handlerScheme != "socks5" {
		t.Fatalf("handler = %q, want %q", handlerScheme, "socks5")
	}
	if listenerScheme != "h3" {
		t.Fatalf("listener = %q, want %q", listenerScheme, "h3")
	}
	if transport != transportH3 {
		t.Fatalf("transport = %q, want %q", transport, transportH3)
	}
}

func TestIsReverseServer(t *testing.T) {
	ep, err := endpoint.Parse("tls://user:pass@:2333?bind=true")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	cfg := config.Config{Listen: ep}
	if !isReverseServer(cfg) {
		t.Fatal("expected bind=true tls to be reverse server")
	}

	epReality, err := endpoint.Parse("reality://uuid@:2333?bind=true")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	cfgReality := config.Config{Listen: epReality}
	if !isReverseServer(cfgReality) {
		t.Fatal("expected bind=true reality to be reverse server")
	}

	ep2, err := endpoint.Parse("tls://:2333")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	cfg2 := config.Config{Listen: ep2}
	if isReverseServer(cfg2) {
		t.Fatal("expected bind=false tls to not be reverse server")
	}
}

func TestIsReverseClient(t *testing.T) {
	listen, err := endpoint.Parse("rtcp://:2222/10.1.1.2:22")
	if err != nil {
		t.Fatalf("parse listen: %v", err)
	}
	forward, err := endpoint.Parse("tls://user:pass@remote:2333")
	if err != nil {
		t.Fatalf("parse forward: %v", err)
	}
	cfg := config.Config{Listen: listen, Forward: &forward}
	if !isReverseClient(cfg) {
		t.Fatal("expected rtcp with forward to be reverse client")
	}
}
