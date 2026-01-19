package http

import (
	"fmt"
	"forward/inner/config"
	"forward/inner/dialer"
)

func init() {
	dialer.Register("http", newDialer)
	dialer.Register("https", newDialer)
}

func newDialer(cfg config.Config) (dialer.Dialer, error) {
	if cfg.Forward == nil {
		return nil, fmt.Errorf("http dialer requires forward")
	}
	return New(cfg)
}
