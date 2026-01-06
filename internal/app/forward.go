package app

import (
	"forward/internal/config"
	"forward/internal/dialer"
	"forward/internal/listener"

	_ "forward/internal/listener/http"
	_ "forward/internal/listener/http3"
	_ "forward/internal/listener/socks5"
	_ "forward/internal/listener/tcp"
	_ "forward/internal/listener/udp"

	_ "forward/internal/dialer/direct"
	_ "forward/internal/dialer/http"
	_ "forward/internal/dialer/quic"
	_ "forward/internal/dialer/socks5"
	_ "forward/internal/dialer/tls"
)

func NewForwarder(cfg config.Config) (listener.Runner, error) {
	d, err := dialer.New(cfg)
	if err != nil {
		return nil, err
	}

	return listener.New(cfg, d)
}
