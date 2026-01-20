package builder

import "testing"

func TestResolveReverseTypes(t *testing.T) {
	tests := []struct {
		scheme        string
		wantConnector string
		wantDialer    string
	}{
		{scheme: "tls", wantConnector: "tcp", wantDialer: "tls"},
		{scheme: "https", wantConnector: "tcp", wantDialer: "tls"},
		{scheme: "quic", wantConnector: "tcp", wantDialer: "quic"},
		{scheme: "http3", wantConnector: "tcp", wantDialer: "quic"},
		{scheme: "reality", wantConnector: "vless", wantDialer: "reality"},
		{scheme: "vless+reality", wantConnector: "vless", wantDialer: "reality"},
		{scheme: "tcp", wantConnector: "tcp", wantDialer: "tcp"},
	}

	for _, tt := range tests {
		conn, dial, err := resolveReverseTypes(tt.scheme)
		if err != nil {
			t.Fatalf("resolveReverseTypes(%q) returned error: %v", tt.scheme, err)
		}
		if conn != tt.wantConnector {
			t.Fatalf("connector = %q, want %q", conn, tt.wantConnector)
		}
		if dial != tt.wantDialer {
			t.Fatalf("dialer = %q, want %q", dial, tt.wantDialer)
		}
	}
}

func TestResolveReverseTypesUnsupported(t *testing.T) {
	if _, _, err := resolveReverseTypes("socks5"); err == nil {
		t.Fatal("expected socks5 to be unsupported")
	}
}
