package handler

import (
	"testing"
	"time"

	"forward/internal/metadata"
)

func TestApplyCommonMetadata(t *testing.T) {
	handshake := time.Second
	udpIdle := 2 * time.Second
	maxSessions := 3
	md := metadata.New(map[string]any{
		"handshake_timeout": 5 * time.Second,
		"udp_idle":          7 * time.Second,
		"max_udp_sessions":  11,
	})

	ApplyHandshakeTimeoutMetadata(md, &handshake)
	ApplyUDPRelayMetadata(md, &udpIdle, &maxSessions)

	if handshake != 5*time.Second {
		t.Fatalf("handshake = %s, want %s", handshake, 5*time.Second)
	}
	if udpIdle != 7*time.Second {
		t.Fatalf("udpIdle = %s, want %s", udpIdle, 7*time.Second)
	}
	if maxSessions != 11 {
		t.Fatalf("maxSessions = %d, want %d", maxSessions, 11)
	}
}
