package tests

import (
	"net/url"
	"strings"
	"testing"

	"forward/base/endpoint"
)

func TestParseBasic(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
		scheme  string
		host    string
		port    int
	}{
		{"tcp_ipv4", "tcp://127.0.0.1:8080", false, "tcp", "127.0.0.1", 8080},
		{"udp_ipv4", "udp://0.0.0.0:5353", false, "udp", "0.0.0.0", 5353},
		{"https", "https://localhost:443", false, "https", "localhost", 443},
		{"socks5", "socks5://192.168.1.1:1080", false, "socks5", "192.168.1.1", 1080},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := endpoint.Parse(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if ep.Scheme != tt.scheme {
				t.Errorf("Scheme = %v, want %v", ep.Scheme, tt.scheme)
			}
			if ep.Host != tt.host {
				t.Errorf("Host = %v, want %v", ep.Host, tt.host)
			}
			if ep.Port != tt.port {
				t.Errorf("Port = %v, want %v", ep.Port, tt.port)
			}
		})
	}
}

func TestParseIPv6(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		host string
		port int
	}{
		{"loopback", "tcp://[::1]:8080", "::1", 8080},
		{"any", "tcp://[::]:1080", "::", 1080},
		{"full", "tcp://[2001:db8::1]:443", "2001:db8::1", 443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := endpoint.Parse(tt.raw)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if ep.Host != tt.host {
				t.Errorf("Host = %v, want %v", ep.Host, tt.host)
			}
			if ep.Port != tt.port {
				t.Errorf("Port = %v, want %v", ep.Port, tt.port)
			}
		})
	}
}

func TestParseSchemeTransport(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		scheme string
	}{
		{"socks5_h2", "socks5+h2://localhost:443", "socks5+h2"},
		{"http_tls", "http+tls://localhost:443", "http+tls"},
		{"tcp_dtls", "tcp+dtls://localhost:5000", "tcp+dtls"},
		{"vless_reality", "vless+reality://localhost:443", "vless+reality"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := endpoint.Parse(tt.raw)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if ep.Scheme != tt.scheme {
				t.Errorf("Scheme = %v, want %v", ep.Scheme, tt.scheme)
			}
		})
	}
}

func TestParseWithUserPass(t *testing.T) {
	raw := "socks5://user:pass@127.0.0.1:1080"
	ep, err := endpoint.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	user, pass, ok := ep.UserPass()
	if !ok {
		t.Error("UserPass() ok = false, want true")
	}
	if user != "user" {
		t.Errorf("user = %v, want user", user)
	}
	if pass != "pass" {
		t.Errorf("pass = %v, want pass", pass)
	}
}

func TestParseWithPath(t *testing.T) {
	raw := "tcp://:8080/10.0.0.1:22"
	ep, err := endpoint.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if ep.FAddress != "10.0.0.1:22" {
		t.Errorf("FAddress = %v, want 10.0.0.1:22", ep.FAddress)
	}
	if ep.RAddress != ":8080" {
		t.Errorf("RAddress = %v, want :8080", ep.RAddress)
	}
}

func TestRedactedString(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		contains    []string
		notContains []string
	}{
		{
			name:        "password_redacted",
			raw:         "socks5://user:secret123@localhost:1080",
			contains:    []string{"user", "redacted"},
			notContains: []string{"secret123"},
		},
		{
			name:        "query_key_redacted",
			raw:         "vless://localhost:443?uuid=abc-123&key=private",
			contains:    []string{"redacted"},
			notContains: []string{"abc-123", "private"},
		},
		{
			name:        "psk_redacted",
			raw:         "tls://localhost:443?psk=secret&sni=example.com",
			contains:    []string{"sni=example.com", "redacted"},
			notContains: []string{"secret"},
		},
		{
			name:        "hysteria2_userinfo_and_obfs_password_redacted",
			raw:         "hysteria2://token-abc@localhost:443?obfs=salamander&obfs-password=secret",
			contains:    []string{"redacted", "obfs=salamander"},
			notContains: []string{"token-abc", "secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := endpoint.Parse(tt.raw)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			redacted := ep.RedactedString()
			for _, s := range tt.contains {
				if !strings.Contains(redacted, s) {
					t.Errorf("RedactedString() = %v, should contain %v", redacted, s)
				}
			}
			for _, s := range tt.notContains {
				if strings.Contains(redacted, s) {
					t.Errorf("RedactedString() = %v, should NOT contain %v", redacted, s)
				}
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"no_scheme", "localhost:8080"},
		{"no_port", "tcp://localhost"},
		{"invalid_port", "tcp://localhost:abc"},
		{"port_zero", "tcp://localhost:0"},
		{"port_too_large", "tcp://localhost:70000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := endpoint.Parse(tt.raw)
			if err == nil {
				t.Errorf("Parse(%q) should return error", tt.raw)
			}
		})
	}
}

func TestAddress(t *testing.T) {
	ep := endpoint.Endpoint{Host: "127.0.0.1", Port: 8080}
	if addr := ep.Address(); addr != "127.0.0.1:8080" {
		t.Errorf("Address() = %v, want 127.0.0.1:8080", addr)
	}
}

func TestHasUserPass(t *testing.T) {
	tests := []struct {
		name string
		user *url.Userinfo
		want bool
	}{
		{"nil", nil, false},
		{"user_only", url.User("admin"), true},
		{"user_pass", url.UserPassword("admin", "secret"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := endpoint.Endpoint{User: tt.user}
			if got := ep.HasUserPass(); got != tt.want {
				t.Errorf("HasUserPass() = %v, want %v", got, tt.want)
			}
		})
	}
}
