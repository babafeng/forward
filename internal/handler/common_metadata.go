package handler

import (
	"time"

	"forward/internal/metadata"
)

func ApplyHandshakeTimeoutMetadata(md metadata.Metadata, timeout *time.Duration) {
	if md == nil || timeout == nil {
		return
	}
	if v := md.Get("handshake_timeout"); v != nil {
		if d, ok := v.(time.Duration); ok && d > 0 {
			*timeout = d
		}
	}
}

func ApplyUDPRelayMetadata(md metadata.Metadata, idle *time.Duration, maxSessions *int) {
	if md == nil {
		return
	}
	if idle != nil {
		if v := md.Get("udp_idle"); v != nil {
			if d, ok := v.(time.Duration); ok && d > 0 {
				*idle = d
			}
		}
	}
	if maxSessions != nil {
		if v := md.Get("max_udp_sessions"); v != nil {
			if n, ok := v.(int); ok && n > 0 {
				*maxSessions = n
			}
		}
	}
}
