package socks5

import (
	"fmt"

	"forward/internal/config"
	"forward/internal/dialer"
)

func init() {
	dialer.Register("socks5", newDialer)
	dialer.Register("socks5h", newDialer)
}

func newDialer(cfg config.Config) (dialer.Dialer, error) {
	if cfg.Proxy == nil {
		return nil, fmt.Errorf("socks5 dialer requires proxy")
	}
	return New(cfg)
}
