package tls

import (
	"forward/internal/config"
	"forward/internal/dialer"
)

func init() {
	dialer.Register("tls", newDialer)
}

func New(cfg config.Config) (dialer.Dialer, error) {
	return newDialer(cfg)
}
