package builder

import "testing"

func TestResolveTypesHTTP2(t *testing.T) {
	tests := []struct {
		scheme        string
		wantConnector string
		wantDialer    string
	}{
		{scheme: "http2", wantConnector: "http", wantDialer: "http2"},
		{scheme: "http+http2", wantConnector: "http", wantDialer: "http2"},
		{scheme: "socks5+http2", wantConnector: "socks5", wantDialer: "http2"},
		{scheme: "socks5h+http2", wantConnector: "socks5", wantDialer: "http2"},
		{scheme: "tcp+http2", wantConnector: "tcp", wantDialer: "http2"},
	}

	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			connectorName, dialerName, err := resolveTypes(tt.scheme)
			if err != nil {
				t.Fatalf("resolveTypes(%q) returned error: %v", tt.scheme, err)
			}
			if connectorName != tt.wantConnector {
				t.Fatalf("connector = %q, want %q", connectorName, tt.wantConnector)
			}
			if dialerName != tt.wantDialer {
				t.Fatalf("dialer = %q, want %q", dialerName, tt.wantDialer)
			}
		})
	}
}

func TestResolveTypesHTTP2Unsupported(t *testing.T) {
	if _, _, err := resolveTypes("udp+http2"); err == nil {
		t.Fatal("expected udp+http2 to be unsupported")
	}
}
