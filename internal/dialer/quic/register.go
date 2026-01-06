package quic

import (
	"forward/internal/config"
	"forward/internal/dialer"
)

func init() {
	dialer.Register("quic", newDialer)
	dialer.Register("http3", newDialer)
}

func newDialer(cfg config.Config) (dialer.Dialer, error) {
	if cfg.Proxy == nil {
		return nil, nil
	}
	return New(*cfg.Proxy, cfg.Insecure)
}
