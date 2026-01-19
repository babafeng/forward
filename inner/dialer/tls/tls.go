package tls

import (
	"forward/inner/config"
	"forward/inner/dialer"
	"forward/inner/dialer/http"
)

func New(cfg config.Config) (dialer.Dialer, error) {
	if cfg.Forward != nil {
		newForward := *cfg.Forward
		newForward.Scheme = "https"
		cfg.Forward = &newForward
	}

	return http.New(cfg)
}
