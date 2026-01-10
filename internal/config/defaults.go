package config

func ApplyDefaults(cfg *Config) {
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
}
