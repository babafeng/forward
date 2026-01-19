package quic

import (
	"fmt"
	"forward/inner/config"
	"forward/inner/dialer"
)

func init() {
	dialer.Register("quic", newDialer)
	dialer.Register("http3", newDialer)
}

func newDialer(cfg config.Config) (dialer.Dialer, error) {
	if cfg.Forward == nil {
		return nil, fmt.Errorf("quic dialer requires forward")
	}
	return New(cfg)
}
