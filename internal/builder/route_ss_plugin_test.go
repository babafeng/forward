package builder

import (
	"testing"

	"forward/base/endpoint"
)

func TestBuildSSConnectorMetadataPluginQueryAmpersand(t *testing.T) {
	ep, err := endpoint.Parse("ss://chacha20-ietf-poly1305:pwd@example.com:443?plugin=obfs&plugin_mode=http&plugin_host=foo.example")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	md := buildSSConnectorMetadata(ep)
	if got := md.GetString("plugin"); got != "obfs" {
		t.Fatalf("plugin = %q, want %q", got, "obfs")
	}
	if got := md.GetString("plugin_mode"); got != "http" {
		t.Fatalf("plugin_mode = %q, want %q", got, "http")
	}
	if got := md.GetString("plugin_host"); got != "foo.example" {
		t.Fatalf("plugin_host = %q, want %q", got, "foo.example")
	}
}

func TestBuildSSConnectorMetadataPluginQuerySemicolon(t *testing.T) {
	ep, err := endpoint.Parse("ss://chacha20-ietf-poly1305:pwd@example.com:443?plugin=obfs-local;obfs=http;obfs-host=foo.example;obfs-uri=/")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	md := buildSSConnectorMetadata(ep)
	if got := md.GetString("plugin"); got != "obfs" {
		t.Fatalf("plugin = %q, want %q", got, "obfs")
	}
	if got := md.GetString("plugin_mode"); got != "http" {
		t.Fatalf("plugin_mode = %q, want %q", got, "http")
	}
	if got := md.GetString("plugin_host"); got != "foo.example" {
		t.Fatalf("plugin_host = %q, want %q", got, "foo.example")
	}
}

func TestBuildSSConnectorMetadataPluginEncoded(t *testing.T) {
	ep, err := endpoint.Parse("ss://chacha20-ietf-poly1305:pwd@example.com:443?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dfoo.example")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	md := buildSSConnectorMetadata(ep)
	if got := md.GetString("plugin"); got != "obfs" {
		t.Fatalf("plugin = %q, want %q", got, "obfs")
	}
	if got := md.GetString("plugin_mode"); got != "http" {
		t.Fatalf("plugin_mode = %q, want %q", got, "http")
	}
	if got := md.GetString("plugin_host"); got != "foo.example" {
		t.Fatalf("plugin_host = %q, want %q", got, "foo.example")
	}
}

func TestBuildSSConnectorMetadataShadowrocketStyle(t *testing.T) {
	ep, err := endpoint.Parse("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpsRTl1TDVmUjN5Ujk@example.com:443?plugin=obfs-local;obfs%3Dhttp;obfs-host%3Dfoo.example;obfs-uri%3D/")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	md := buildSSConnectorMetadata(ep)
	if got := md.GetString("method"); got != "chacha20-ietf-poly1305" {
		t.Fatalf("method = %q, want %q", got, "chacha20-ietf-poly1305")
	}
	if got := md.GetString("password"); got != "lE9uL5fR3yR9" {
		t.Fatalf("password = %q, want %q", got, "lE9uL5fR3yR9")
	}
	if got := md.GetString("plugin"); got != "obfs" {
		t.Fatalf("plugin = %q, want %q", got, "obfs")
	}
	if got := md.GetString("plugin_mode"); got != "http" {
		t.Fatalf("plugin_mode = %q, want %q", got, "http")
	}
	if got := md.GetString("plugin_host"); got != "foo.example" {
		t.Fatalf("plugin_host = %q, want %q", got, "foo.example")
	}
}
