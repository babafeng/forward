package tls

import (
	"context"
	"net"

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

type Dialer struct {
	base dialer.Dialer
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.base.DialContext(ctx, network, address)
}
