package http

import (
	"forward/internal/config"
	"forward/internal/dialer"
)

func init() {
	dialer.Register("http", newDialer)
	dialer.Register("https", newDialer)
}

func New(cfg config.Config) (dialer.Dialer, error) {
	return newDialer(cfg)
}
