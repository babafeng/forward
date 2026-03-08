package dialer

import (
	"testing"
	"time"

	"forward/internal/metadata"
)

func TestParsePHTTransportMetadata(t *testing.T) {
	md := metadata.New(map[string]any{
		"host":              " example.com ",
		"keepalive":         "yes",
		"ttl":               "3s",
		"keepalive_period":  "5s",
		"handshake_timeout": "7",
		"max_idle_timeout":  9 * time.Second,
		"max_streams":       "11",
		"authorize_path":    "/auth",
		"push_path":         "push",
		"pull_path":         "/pull2",
		"secret":            "token",
	})

	got := ParsePHTTransportMetadata(md)
	if got.Host != "example.com" {
		t.Fatalf("Host = %q, want %q", got.Host, "example.com")
	}
	if got.KeepAlivePeriod != 5*time.Second {
		t.Fatalf("KeepAlivePeriod = %s, want %s", got.KeepAlivePeriod, 5*time.Second)
	}
	if got.HandshakeTimeout != 7*time.Second {
		t.Fatalf("HandshakeTimeout = %s, want %s", got.HandshakeTimeout, 7*time.Second)
	}
	if got.MaxIdleTimeout != 9*time.Second {
		t.Fatalf("MaxIdleTimeout = %s, want %s", got.MaxIdleTimeout, 9*time.Second)
	}
	if got.MaxStreams != 11 {
		t.Fatalf("MaxStreams = %d, want %d", got.MaxStreams, 11)
	}
	if got.AuthorizePath != "/auth" {
		t.Fatalf("AuthorizePath = %q, want %q", got.AuthorizePath, "/auth")
	}
	if got.PushPath != "/push" {
		t.Fatalf("PushPath = %q, want default %q", got.PushPath, "/push")
	}
	if got.PullPath != "/pull2" {
		t.Fatalf("PullPath = %q, want %q", got.PullPath, "/pull2")
	}
	if got.Secret != "token" {
		t.Fatalf("Secret = %q, want %q", got.Secret, "token")
	}
}
