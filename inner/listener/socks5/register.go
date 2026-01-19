package socks5

import (
	"fmt"
	"strings"

	"forward/inner/config"
	"forward/inner/dialer"
	hsocks5 "forward/inner/handler/socks5"
	"forward/inner/listener"
)

func init() {
	listener.Register("socks5", newRunner)
	listener.Register("socks5h", newRunner)
}

func newRunner(cfg config.Config, d dialer.Dialer) (listener.Runner, error) {
	scheme := strings.ToLower(cfg.Listen.Scheme)
	if scheme != "socks5" && scheme != "socks5h" {
		return nil, fmt.Errorf("socks5 listener requires scheme socks5/socks5h, got %s", cfg.Listen.Scheme)
	}
	h := hsocks5.New(cfg, d)
	return New(cfg, h), nil
}
