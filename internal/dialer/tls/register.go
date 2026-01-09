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
	if cfg.Forward == nil {
		return nil, fmt.Errorf("tls dialer requires forward")
	}
	return New(cfg)
}
