package tests

import (
	"testing"

	"forward/inner/config"
	cjson "forward/inner/config/json"
	"forward/inner/dialer"
	"forward/base/endpoint"

	_ "forward/inner/dialer/http"
)

func TestJSONForwardsChain(t *testing.T) {
	raw := []byte(`{"listeners":["http://:8080"],"forwards":["http://S2:8080","http://S1:8080"]}`)
	cfg, err := cjson.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	if len(cfg.ForwardChain) != 2 {
		t.Fatalf("ForwardChain len = %d, want 2", len(cfg.ForwardChain))
	}
	if cfg.Forward == nil {
		t.Fatal("Forward should not be nil")
	}
	if cfg.Forward.Host != "S1" || cfg.Forward.Port != 8080 {
		t.Fatalf("Forward = %s:%d, want S1:8080", cfg.Forward.Host, cfg.Forward.Port)
	}
	if cfg.ForwardChain[0].Host != "S2" {
		t.Fatalf("ForwardChain[0].Host = %s, want S2", cfg.ForwardChain[0].Host)
	}
}

func TestJSONForwardAndForwardsExclusive(t *testing.T) {
	raw := []byte(`{"listeners":["http://:8080"],"forward":"http://S1:8080","forwards":["http://S2:8080"]}`)
	if _, err := cjson.Parse(raw); err == nil {
		t.Fatal("expected error when forward and forwards are both set")
	}
}

func TestDialerForwardChainHTTP(t *testing.T) {
	hop1, err := endpoint.Parse("http://S2:8080")
	if err != nil {
		t.Fatalf("Parse hop1 failed: %v", err)
	}
	hop2, err := endpoint.Parse("http://S1:8080")
	if err != nil {
		t.Fatalf("Parse hop2 failed: %v", err)
	}
	cfg := config.Config{
		ForwardChain: []endpoint.Endpoint{hop1, hop2},
	}
	d, err := dialer.New(cfg)
	if err != nil {
		t.Fatalf("dialer.New() failed: %v", err)
	}
	if d == nil {
		t.Fatal("dialer.New() returned nil")
	}
}
