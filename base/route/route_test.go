package route

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestCurrentHomeDirFallsBackWhenHOMEEmpty(t *testing.T) {
	oldHome, hadHome := os.LookupEnv("HOME")
	t.Cleanup(func() {
		if hadHome {
			_ = os.Setenv("HOME", oldHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
	})
	_ = os.Setenv("HOME", "")

	home, err := currentHomeDir()
	if err != nil {
		t.Fatalf("currentHomeDir failed: %v", err)
	}
	if strings.TrimSpace(home) == "" {
		t.Fatal("home is empty")
	}
}

func TestDecideContinuesWhenAuxiliaryDNSLookupFails(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.31.110/32")
	r, err := NewRouter(&Config{
		SkipProxy: []netip.Prefix{prefix},
		Rules: []Rule{
			{
				Type: RuleFinal,
				Action: Action{
					Type: ActionDirect,
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewRouter failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	decision, err := r.Decide(ctx, "example.com:443")
	if err != nil {
		t.Fatalf("Decide returned DNS error: %v", err)
	}
	if !decision.Matched || decision.Via != "DIRECT" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestParseDNSServerSupportsSecureTransports(t *testing.T) {
	tests := []struct {
		raw         string
		kind        dnsServerKind
		network     string
		address     string
		url         string
		serverName  string
		wantPresent bool
	}{
		{raw: "192.168.31.1", kind: dnsServerPlain, address: "192.168.31.1:53", wantPresent: true},
		{raw: "::1", kind: dnsServerPlain, address: "[::1]:53", wantPresent: true},
		{raw: "[::1]", kind: dnsServerPlain, address: "[::1]:53", wantPresent: true},
		{raw: "tcp://1.1.1.1", kind: dnsServerPlain, network: "tcp", address: "1.1.1.1:53", wantPresent: true},
		{raw: "https://dns.google/dns-query", kind: dnsServerDoH, url: "https://dns.google/dns-query", wantPresent: true},
		{raw: "tls://1.1.1.1", kind: dnsServerDoT, address: "1.1.1.1:853", serverName: "1.1.1.1", wantPresent: true},
		{raw: "dot://dns.google:853", kind: dnsServerDoT, address: "dns.google:853", serverName: "dns.google", wantPresent: true},
		{raw: "", wantPresent: false},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, ok := parseDNSServer(tt.raw)
			if ok != tt.wantPresent {
				t.Fatalf("ok = %v, want %v", ok, tt.wantPresent)
			}
			if !ok {
				return
			}
			if got.kind != tt.kind || got.network != tt.network || got.address != tt.address || got.url != tt.url || got.serverName != tt.serverName {
				t.Fatalf("server = %#v", got)
			}
		})
	}
}
