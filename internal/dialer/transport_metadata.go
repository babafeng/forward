package dialer

import (
	"strings"
	"time"

	"forward/internal/metadata"
)

type TransportMetadata struct {
	Host             string
	KeepAlivePeriod  time.Duration
	HandshakeTimeout time.Duration
	MaxIdleTimeout   time.Duration
	MaxStreams       int
}

type PHTTransportMetadata struct {
	TransportMetadata
	AuthorizePath string
	PushPath      string
	PullPath      string
	Secret        string
}

func ParseTransportMetadata(md metadata.Metadata) TransportMetadata {
	var tm TransportMetadata
	if md == nil {
		return tm
	}

	if v := metadata.StringValue(md.Get("host")); v != "" {
		tm.Host = v
	}
	if metadata.BoolValue(md.Get("keepalive")) {
		if v := metadata.DurationValue(md.Get("ttl")); v > 0 {
			tm.KeepAlivePeriod = v
		}
		if v := metadata.DurationValue(md.Get("keepalive_period")); v > 0 {
			tm.KeepAlivePeriod = v
		}
	}
	if v := metadata.DurationValue(md.Get("handshake_timeout")); v > 0 {
		tm.HandshakeTimeout = v
	}
	if v := metadata.DurationValue(md.Get("max_idle_timeout")); v > 0 {
		tm.MaxIdleTimeout = v
	}
	if v := metadata.IntValue(md.Get("max_streams")); v > 0 {
		tm.MaxStreams = v
	}
	return tm
}

func ParsePHTTransportMetadata(md metadata.Metadata) PHTTransportMetadata {
	tm := PHTTransportMetadata{
		TransportMetadata: ParseTransportMetadata(md),
		AuthorizePath:     "/authorize",
		PushPath:          "/push",
		PullPath:          "/pull",
	}
	if md == nil {
		return tm
	}

	if v := metadata.StringValue(md.Get("authorize_path")); v != "" {
		tm.AuthorizePath = normalizePath(v, tm.AuthorizePath)
	}
	if v := metadata.StringValue(md.Get("push_path")); v != "" {
		tm.PushPath = normalizePath(v, tm.PushPath)
	}
	if v := metadata.StringValue(md.Get("pull_path")); v != "" {
		tm.PullPath = normalizePath(v, tm.PullPath)
	}
	if v := metadata.StringValue(md.Get("secret")); v != "" {
		tm.Secret = v
	}
	return tm
}

func normalizePath(v, fallback string) string {
	if v == "" {
		return fallback
	}
	if !strings.HasPrefix(v, "/") {
		return fallback
	}
	return v
}
