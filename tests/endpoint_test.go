package tests

import (
	"encoding/base64"
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

func TestParseHTMLEscapedQuery(t *testing.T) {
	ep, err := endpoint.Parse("vless://uuid@127.0.0.1:443?encryption=none&amp;flow=xtls-rprx-vision&amp;mux=true")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if got := ep.Query.Get("flow"); got != "xtls-rprx-vision" {
		t.Fatalf("flow = %q", got)
	}
	if got := ep.Query.Get("mux"); got != "true" {
		t.Fatalf("mux = %q", got)
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

func TestParseVmessBase64Endpoint(t *testing.T) {
	raw := "vmess://YXV0bzpjZTU5ZmJlYy0wNWQxLTQ3ZmMtYWMxZi03MmVjMjE5YTc1MzBAMTc4LjE1Ny42MS4xMjQ6MTI1Mjk?remarks=JMS-846412@c60s4.portablesubmarines.com:12529&alterId=0"
	ep, err := endpoint.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if ep.Scheme != "vmess" {
		t.Errorf("Scheme = %v, want vmess", ep.Scheme)
	}
	if ep.Host != "178.157.61.124" {
		t.Errorf("Host = %v, want 178.157.61.124", ep.Host)
	}
	if ep.Port != 12529 {
		t.Errorf("Port = %v, want 12529", ep.Port)
	}
	user, pass, ok := ep.UserPass()
	if !ok {
		t.Fatal("UserPass() ok = false, want true")
	}
	if user != "auto" {
		t.Errorf("user = %v, want auto", user)
	}
	if pass != "ce59fbec-05d1-47fc-ac1f-72ec219a7530" {
		t.Errorf("pass = %v, want ce59fbec-05d1-47fc-ac1f-72ec219a7530", pass)
	}
	if ep.Query.Get("alterId") != "0" {
		t.Errorf("alterId = %v, want 0", ep.Query.Get("alterId"))
	}
	if ep.Query.Get("remarks") != "JMS-846412@c60s4.portablesubmarines.com:12529" {
		t.Errorf("remarks = %v", ep.Query.Get("remarks"))
	}
}

func TestParseBase64AuthorityForAllSchemes(t *testing.T) {
	tests := []struct {
		name     string
		scheme   string
		decoded  string
		query    string
		wantHost string
		wantPort int
		wantUser string
		wantPass string
		wantQKey string
		wantQVal string
	}{
		{
			name:     "tcp_host_port",
			scheme:   "tcp",
			decoded:  "203.0.113.10:8080",
			query:    "bind=true",
			wantHost: "203.0.113.10",
			wantPort: 8080,
			wantQKey: "bind",
			wantQVal: "true",
		},
		{
			name:     "socks5_user_pass",
			scheme:   "socks5",
			decoded:  "user:pa/ss@127.0.0.1:1080",
			wantHost: "127.0.0.1",
			wantPort: 1080,
			wantUser: "user",
			wantPass: "pa/ss",
		},
		{
			name:     "http_user_pass",
			scheme:   "http",
			decoded:  "user:pass@example.com:8080",
			wantHost: "example.com",
			wantPort: 8080,
			wantUser: "user",
			wantPass: "pass",
		},
		{
			name:     "vless_uuid",
			scheme:   "vless",
			decoded:  "uuid-123@example.com:443",
			query:    "security=tls&type=ws",
			wantHost: "example.com",
			wantPort: 443,
			wantUser: "uuid-123",
			wantQKey: "security",
			wantQVal: "tls",
		},
		{
			name:     "trojan_password",
			scheme:   "trojan",
			decoded:  "secret@example.net:443",
			query:    "sni=example.net",
			wantHost: "example.net",
			wantPort: 443,
			wantUser: "secret",
			wantQKey: "sni",
			wantQVal: "example.net",
		},
		{
			name:     "hy2_password",
			scheme:   "hy2",
			decoded:  "token@example.org:8443",
			wantHost: "example.org",
			wantPort: 8443,
			wantUser: "token",
		},
		{
			name:     "vmess_security_uuid",
			scheme:   "vmess",
			decoded:  "auto:ce59fbec-05d1-47fc-ac1f-72ec219a7530@178.157.61.124:12529",
			query:    "alterId=0",
			wantHost: "178.157.61.124",
			wantPort: 12529,
			wantUser: "auto",
			wantPass: "ce59fbec-05d1-47fc-ac1f-72ec219a7530",
			wantQKey: "alterId",
			wantQVal: "0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.scheme + "://" + base64.RawURLEncoding.EncodeToString([]byte(tt.decoded))
			if tt.query != "" {
				raw += "?" + tt.query
			}

			ep, err := endpoint.Parse(raw)
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", raw, err)
			}
			if ep.Scheme != tt.scheme {
				t.Errorf("Scheme = %q, want %q", ep.Scheme, tt.scheme)
			}
			if ep.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", ep.Host, tt.wantHost)
			}
			if ep.Port != tt.wantPort {
				t.Errorf("Port = %d, want %d", ep.Port, tt.wantPort)
			}
			user, pass, ok := ep.UserPass()
			if tt.wantUser == "" && ok {
				t.Fatalf("UserPass() = (%q, %q, true), want no userinfo", user, pass)
			}
			if tt.wantUser != "" {
				if !ok {
					t.Fatal("UserPass() ok = false, want true")
				}
				if user != tt.wantUser {
					t.Errorf("user = %q, want %q", user, tt.wantUser)
				}
				if pass != tt.wantPass {
					t.Errorf("pass = %q, want %q", pass, tt.wantPass)
				}
			}
			if tt.wantQKey != "" && ep.Query.Get(tt.wantQKey) != tt.wantQVal {
				t.Errorf("query %s = %q, want %q", tt.wantQKey, ep.Query.Get(tt.wantQKey), tt.wantQVal)
			}
		})
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
