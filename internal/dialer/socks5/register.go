package socks5

import (
	"forward/internal/config"
	"forward/internal/dialer"
)

func init() {
	dialer.Register("socks5", newDialer)
	dialer.Register("socks5h", newDialer)
}

func newDialer(cfg config.Config) (dialer.Dialer, error) {
	return New(*cfg.Proxy)
}
