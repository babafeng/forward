package builder

import (
	"net/url"
	"testing"
	"time"

	"forward/base/endpoint"
	"forward/internal/metadata"
)

func TestParseMuxConfig(t *testing.T) {
	q := url.Values{
		"mux":             []string{"true"},
		"mux_max_streams": []string{"64"},
		"mux_idle":        []string{"30s"},
	}
	enabled, maxStreams, idle := parseMuxConfig(q)
	if !enabled {
		t.Fatalf("enabled = %v, want true", enabled)
	}
	if maxStreams != 64 {
		t.Fatalf("max streams = %d, want 64", maxStreams)
	}
	if idle != 30*time.Second {
		t.Fatalf("idle = %s, want 30s", idle)
	}
}

func TestParseMuxConfigFallbackKeys(t *testing.T) {
	q := url.Values{
		"mux":             []string{"1"},
		"mux_concurrency": []string{"16"},
		"mux_idle_timeout": []string{
			"45",
		},
	}
	enabled, maxStreams, idle := parseMuxConfig(q)
	if !enabled {
		t.Fatalf("enabled = %v, want true", enabled)
	}
	if maxStreams != 16 {
		t.Fatalf("max streams = %d, want 16", maxStreams)
	}
	if idle != 45*time.Second {
		t.Fatalf("idle = %s, want 45s", idle)
	}
}

func TestBuildVlessConnectorMetadataMux(t *testing.T) {
	ep, err := endpoint.Parse("vless://id@127.0.0.1:443?flow=xtls-rprx-vision&encryption=none&mux=true&mux_max_streams=32&mux_idle=20s")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	md := buildVlessConnectorMetadata(ep)
	if !md.GetBool(metadata.KeyMux) {
		t.Fatalf("mux = false, want true")
	}
	if md.GetInt(metadata.KeyMuxMax) != 32 {
		t.Fatalf("mux max = %d, want 32", md.GetInt(metadata.KeyMuxMax))
	}
	if got, ok := md.Get(metadata.KeyMuxIdle).(time.Duration); !ok || got != 20*time.Second {
		t.Fatalf("mux idle = %v, want 20s", md.Get(metadata.KeyMuxIdle))
	}
}

func TestBuildVmessConnectorMetadataMux(t *testing.T) {
	ep, err := endpoint.Parse("vmess://auto:id@127.0.0.1:443?alterId=0&mux=true&mux_concurrency=8&mux_idle_timeout=15")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	md := buildVmessConnectorMetadata(ep)
	if !md.GetBool(metadata.KeyMux) {
		t.Fatalf("mux = false, want true")
	}
	if md.GetInt(metadata.KeyMuxMax) != 8 {
		t.Fatalf("mux max = %d, want 8", md.GetInt(metadata.KeyMuxMax))
	}
	if got, ok := md.Get(metadata.KeyMuxIdle).(time.Duration); !ok || got != 15*time.Second {
		t.Fatalf("mux idle = %v, want 15s", md.Get(metadata.KeyMuxIdle))
	}
}
