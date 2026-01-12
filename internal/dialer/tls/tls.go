package tls

import (
	"forward/internal/config"
	"forward/internal/dialer"
	"forward/internal/dialer/http"
)

func New(cfg config.Config) (dialer.Dialer, error) {
	if cfg.Forward != nil {
		newForward := *cfg.Forward
		newForward.Scheme = "https"
		cfg.Forward = &newForward
	}

	return http.New(cfg)
}
