package tests

import (
	"testing"

	"forward/internal/endpoint"
)

func TestParseTCP(t *testing.T) {
	ep, err := endpoint.Parse("tcp://127.0.0.1:2222")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if ep.Scheme != "tcp" {
		t.Fatalf("scheme: want tcp, got %s", ep.Scheme)
	}
	if ep.Host != "127.0.0.1" || ep.Port != 2222 {
		t.Fatalf("addr: got %s:%d", ep.Host, ep.Port)
	}
	if ep.Address() != "127.0.0.1:2222" {
		t.Fatalf("Address(): %s", ep.Address())
	}
}

func TestParseNewFormat(t *testing.T) {
	tests := []struct {
		raw     string
		wantR   string
		wantF   string
		wantErr bool
	}{
		{
			raw:   "tcp://127.0.0.1:2222",
			wantR: "",
			wantF: "",
		},
		{
			raw:   "tcp://:2222/10.0.0.10:22",
			wantR: ":2222",
			wantF: "10.0.0.10:22",
		},
		{
			raw:   "tcp://127.0.0.1:2222/10.0.0.10:22",
			wantR: "127.0.0.1:2222",
			wantF: "10.0.0.10:22",
		},
		{
			raw:   "tcp://0.0.0.0:2222/10.0.0.10:22",
			wantR: "0.0.0.0:2222",
			wantF: "10.0.0.10:22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := endpoint.Parse(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.RAddress != tt.wantR {
				t.Errorf("Parse() RAddress = %v, want %v", got.RAddress, tt.wantR)
			}
			if got.FAddress != tt.wantF {
				t.Errorf("Parse() FAddress = %v, want %v", got.FAddress, tt.wantF)
			}
		})
	}
}

func TestParseSocks5UserPass(t *testing.T) {
	ep, err := endpoint.Parse("socks5://user:pass@127.0.0.1:1080")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	user, pass, ok := ep.UserPass()
	if !ok || user != "user" || pass != "pass" {
		t.Fatalf("UserPass(): got (%q,%q,%v)", user, pass, ok)
	}
}

func TestParseIPv6(t *testing.T) {
	ep, err := endpoint.Parse("tcp://[::1]:80")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if ep.Host != "::1" || ep.Port != 80 {
		t.Fatalf("got %s:%d", ep.Host, ep.Port)
	}
	if ep.Address() != "[::1]:80" {
		t.Fatalf("Address(): %s", ep.Address())
	}
}
