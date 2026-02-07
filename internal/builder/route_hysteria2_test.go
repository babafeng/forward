package builder

import (
	"testing"

	"forward/base/endpoint"
)

func mustParseEndpoint(t *testing.T, raw string) endpoint.Endpoint {
	t.Helper()
	ep, err := endpoint.Parse(raw)
	if err != nil {
		t.Fatalf("parse endpoint %q: %v", raw, err)
	}
	return ep
}

func TestBuildHysteria2DialerMetadataSNIAndPeer(t *testing.T) {
	ep := mustParseEndpoint(t, "hysteria2://token@127.0.0.1:443?peer=peer.example.com")
	md := buildHysteria2DialerMetadata(ep, false)
	if got := md.GetString("sni"); got != "peer.example.com" {
		t.Fatalf("sni from peer = %q, want %q", got, "peer.example.com")
	}

	ep = mustParseEndpoint(t, "hysteria2://token@127.0.0.1:443?sni=sni.example.com&peer=peer.example.com")
	md = buildHysteria2DialerMetadata(ep, false)
	if got := md.GetString("sni"); got != "sni.example.com" {
		t.Fatalf("sni preference = %q, want %q", got, "sni.example.com")
	}
}

func TestBuildHysteria2DialerMetadataInsecureOverride(t *testing.T) {
	ep := mustParseEndpoint(t, "hysteria2://token@127.0.0.1:443")
	md := buildHysteria2DialerMetadata(ep, true)
	if !md.GetBool("insecure") {
		t.Fatalf("insecure should inherit cfg default true")
	}

	ep = mustParseEndpoint(t, "hysteria2://token@127.0.0.1:443?insecure=0")
	md = buildHysteria2DialerMetadata(ep, true)
	if md.GetBool("insecure") {
		t.Fatalf("insecure query should override cfg default")
	}

	ep = mustParseEndpoint(t, "hysteria2://token@127.0.0.1:443?insecure=1")
	md = buildHysteria2DialerMetadata(ep, false)
	if !md.GetBool("insecure") {
		t.Fatalf("insecure query should override cfg default")
	}
}

func TestBuildHysteria2DialerMetadataAuthDecode(t *testing.T) {
	ep := mustParseEndpoint(t, "hysteria2://abc%3Adef@127.0.0.1:443")
	md := buildHysteria2DialerMetadata(ep, false)
	if got := md.GetString("auth"); got != "abc:def" {
		t.Fatalf("auth decode = %q, want %q", got, "abc:def")
	}
}

func TestResolveTypesHysteria2(t *testing.T) {
	connector, dialer, err := resolveTypes("hysteria2")
	if err != nil {
		t.Fatalf("resolveTypes(hysteria2): %v", err)
	}
	if connector != "hysteria2" || dialer != "hysteria2" {
		t.Fatalf("resolveTypes(hysteria2) = (%q, %q)", connector, dialer)
	}

	connector, dialer, err = resolveTypes("hy2")
	if err != nil {
		t.Fatalf("resolveTypes(hy2): %v", err)
	}
	if connector != "hysteria2" || dialer != "hysteria2" {
		t.Fatalf("resolveTypes(hy2) = (%q, %q)", connector, dialer)
	}
}
