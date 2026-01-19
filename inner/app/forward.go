package app

import (
	"forward/inner/config"
	"forward/inner/dialer"
	"forward/inner/listener"

	_ "forward/inner/listener/http"
	_ "forward/inner/listener/http3"
	_ "forward/inner/listener/reverse"
	_ "forward/inner/listener/socks5"
	_ "forward/inner/listener/tcp"
	_ "forward/inner/listener/udp"
	_ "forward/inner/listener/vless"

	_ "forward/inner/dialer/direct"
	_ "forward/inner/dialer/http"
	_ "forward/inner/dialer/quic"
	_ "forward/inner/dialer/socks5"
	_ "forward/inner/dialer/tls"
	_ "forward/inner/dialer/vless"
)

func NewForwarder(cfg config.Config) (listener.Runner, error) {
	d, err := dialer.New(cfg)
	if err != nil {
		return nil, err
	}

	return listener.New(cfg, d)
}
