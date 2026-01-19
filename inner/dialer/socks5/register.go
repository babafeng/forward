package socks5

import (
	"fmt"

	"forward/inner/config"
	"forward/inner/dialer"
)

func init() {
	dialer.Register("socks5", newDialer)
	dialer.Register("socks5h", newDialer)
}

func newDialer(cfg config.Config) (dialer.Dialer, error) {
	if cfg.Forward == nil {
		return nil, fmt.Errorf("socks5 dialer requires forward")
	}
	return New(cfg)
}
