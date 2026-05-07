package builder

import (
	"net/url"
	"testing"
	"time"

	"forward/base/endpoint"
	"forward/internal/config"
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

func TestBuildVlessConnectorMetadataShadowrocketUserInfo(t *testing.T) {
	ep, err := endpoint.Parse("vless://none:0e467f5f-0a5c-44f8-82a5-07f803d161e8@1.2.3.4:443?tls=1&peer=swscan.apple.com&xtls=2&pbk=A0ADElLyacApk2_prdYRh_lsOhG7dMeEVLc_NVFRGA8&sid=d003cb13")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	md := buildVlessConnectorMetadata(ep)
	if got := md.GetString(metadata.KeyUUID); got != "0e467f5f-0a5c-44f8-82a5-07f803d161e8" {
		t.Fatalf("uuid = %q", got)
	}

	dialerMD := buildDialerMetadata(ep)
	if got := dialerMD.GetString(metadata.KeySNI); got != "swscan.apple.com" {
		t.Fatalf("sni = %q", got)
	}
}

func TestBuildRouteAcceptsShadowrocketVlessUserInfo(t *testing.T) {
	ep, err := endpoint.Parse("vless://none:0e467f5f-0a5c-44f8-82a5-07f803d161e8@1.2.3.4:443?tls=1&peer=swscan.apple.com&xtls=2&pbk=A0ADElLyacApk2_prdYRh_lsOhG7dMeEVLc_NVFRGA8&sid=d003cb13")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	route, err := BuildRoute(config.Config{}, []endpoint.Endpoint{ep})
	if err != nil {
		t.Fatalf("BuildRoute failed: %v", err)
	}
	if route == nil {
		t.Fatal("route nil")
	}
}

func TestBuildRouteAcceptsVlessVisionTLS(t *testing.T) {
	ep, err := endpoint.Parse("vless+tls://b1fb1a1c-1f12-470b-9dfb-087f3323f1fb@example.com:11889?security=tls&sni=example.com&flow=xtls-rprx-vision")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	dialerMD := buildDialerMetadata(ep)
	if got := dialerMD.GetString(metadata.KeySecurity); got != "tls" {
		t.Fatalf("security = %q, want tls", got)
	}

	route, err := BuildRoute(config.Config{}, []endpoint.Endpoint{ep})
	if err != nil {
		t.Fatalf("BuildRoute failed: %v", err)
	}
	if route == nil {
		t.Fatal("route nil")
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

func TestBuildTrojanConnectorMetadata(t *testing.T) {
	ep, err := endpoint.Parse("trojan://secret@127.0.0.1:443")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	md := buildTrojanConnectorMetadata(ep)
	if got := md.GetString(metadata.KeyPassword); got != "secret" {
		t.Fatalf("password = %q, want secret", got)
	}
}

func TestBuildRouteAcceptsTrojan(t *testing.T) {
	ep, err := endpoint.Parse("trojan://secret@127.0.0.1:443")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	route, err := BuildRoute(config.Config{Insecure: true}, []endpoint.Endpoint{ep})
	if err != nil {
		t.Fatalf("BuildRoute failed: %v", err)
	}
	if route == nil {
		t.Fatal("route nil")
	}
}
