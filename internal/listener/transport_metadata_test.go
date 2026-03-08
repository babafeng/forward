package listener

import (
	"testing"
	"time"

	"forward/internal/metadata"
)

func TestParsePHTTransportMetadata(t *testing.T) {
	md := metadata.New(map[string]any{
		"backlog":           "64",
		"keepalive":         "on",
		"ttl":               "4s",
		"keepalive_period":  "6s",
		"handshake_timeout": "8",
		"max_idle_timeout":  10 * time.Second,
		"max_streams":       "12",
		"secret":            12345,
	})

	got := ParsePHTTransportMetadata(md, 128)
	if got.Backlog != 64 {
		t.Fatalf("Backlog = %d, want %d", got.Backlog, 64)
	}
	if got.KeepAlivePeriod != 6*time.Second {
		t.Fatalf("KeepAlivePeriod = %s, want %s", got.KeepAlivePeriod, 6*time.Second)
	}
	if got.HandshakeTimeout != 8*time.Second {
		t.Fatalf("HandshakeTimeout = %s, want %s", got.HandshakeTimeout, 8*time.Second)
	}
	if got.MaxIdleTimeout != 10*time.Second {
		t.Fatalf("MaxIdleTimeout = %s, want %s", got.MaxIdleTimeout, 10*time.Second)
	}
	if got.MaxStreams != 12 {
		t.Fatalf("MaxStreams = %d, want %d", got.MaxStreams, 12)
	}
	if got.Secret != "12345" {
		t.Fatalf("Secret = %q, want %q", got.Secret, "12345")
	}
}
