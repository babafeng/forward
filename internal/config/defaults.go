package config

import "time"

func ApplyDefaults(cfg *Config) {
	if cfg.MaxUDPSessions <= 0 {
		cfg.MaxUDPSessions = DefaultMaxUDPSessions
	}
	if cfg.UDPIdleTimeout == 0 {
		cfg.UDPIdleTimeout = DefaultUDPIdleTimeout
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.DialKeepAlive == 0 {
		cfg.DialKeepAlive = DefaultDialKeepAlive
	}
	if cfg.ReadHeaderTimeout == 0 {
		cfg.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if cfg.MaxHeaderBytes == 0 {
		cfg.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.DNSParameters.Timeout == 0 {
		cfg.DNSParameters.Timeout = 5 * time.Second
	}
}
