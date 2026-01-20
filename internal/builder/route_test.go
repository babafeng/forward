package builder

import "testing"

func TestResolveTypesSchemes(t *testing.T) {
	tests := []struct {
		scheme        string
		wantConnector string
		wantDialer    string
	}{
		{scheme: "http2", wantConnector: "http2", wantDialer: "tls"},
		{scheme: "http3", wantConnector: "http3", wantDialer: "http3"},
		{scheme: "tls", wantConnector: "http", wantDialer: "tls"},
		{scheme: "h2", wantConnector: "http", wantDialer: "h2"},
		{scheme: "h3", wantConnector: "http", wantDialer: "h3"},
		{scheme: "socks5+h2", wantConnector: "socks5", wantDialer: "h2"},
		{scheme: "socks5+h3", wantConnector: "socks5", wantDialer: "h3"},
		{scheme: "socks5h+h2", wantConnector: "socks5", wantDialer: "h2"},
		{scheme: "tcp+h3", wantConnector: "tcp", wantDialer: "h3"},
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

func TestResolveTypesUnsupported(t *testing.T) {
	if _, _, err := resolveTypes("udp+h2"); err == nil {
		t.Fatal("expected udp+h2 to be unsupported")
	}
}
