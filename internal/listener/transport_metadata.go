package listener

import (
	"fmt"
	"time"

	"forward/internal/metadata"
)

type TransportMetadata struct {
	Backlog          int
	KeepAlivePeriod  time.Duration
	HandshakeTimeout time.Duration
	MaxIdleTimeout   time.Duration
	MaxStreams       int
}

type PHTTransportMetadata struct {
	TransportMetadata
	Secret string
}

func ParseTransportMetadata(md metadata.Metadata, defaultBacklog int) TransportMetadata {
	tm := TransportMetadata{Backlog: defaultBacklog}
	if md == nil {
		return tm
	}

	if v := metadata.IntValue(md.Get("backlog")); v > 0 {
		tm.Backlog = v
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

func ParsePHTTransportMetadata(md metadata.Metadata, defaultBacklog int) PHTTransportMetadata {
	tm := PHTTransportMetadata{
		TransportMetadata: ParseTransportMetadata(md, defaultBacklog),
	}
	if md == nil {
		return tm
	}
	if v := md.Get("secret"); v != nil {
		tm.Secret = fmt.Sprintf("%v", v)
	}
	return tm
}
