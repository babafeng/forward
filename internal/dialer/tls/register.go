package tls

import (
	"fmt"
	"forward/internal/config"
	"forward/internal/dialer"
)

func init() {
	dialer.Register("tls", newDialer)
}

func newDialer(cfg config.Config) (dialer.Dialer, error) {
	if cfg.Proxy == nil {
		return nil, fmt.Errorf("tls dialer requires proxy")
	}
	return New(cfg)
}
