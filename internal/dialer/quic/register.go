package quic

import (
	"fmt"
	"forward/internal/config"
	"forward/internal/dialer"
)

func init() {
	dialer.Register("quic", newDialer)
	dialer.Register("http3", newDialer)
}

func newDialer(cfg config.Config) (dialer.Dialer, error) {
	if cfg.Proxy == nil {
		return nil, fmt.Errorf("quic dialer requires proxy")
	}
	return New(cfg)
}
