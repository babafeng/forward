package app

import "testing"

func TestSplitSchemeTransportHTTP2(t *testing.T) {
	tests := []struct {
		scheme        string
		wantBase      string
		wantTransport transportKind
	}{
		{scheme: "http2", wantBase: "http", wantTransport: transportH2},
		{scheme: "http+http2", wantBase: "http", wantTransport: transportH2},
		{scheme: "socks5+http2", wantBase: "socks5", wantTransport: transportH2},
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
	if transport != transportH2 {
		t.Fatalf("transport = %q, want %q", transport, transportH2)
	}
}
