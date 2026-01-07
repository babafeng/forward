package http

import (
	"fmt"
	"strings"

	"forward/internal/config"
	tlsconfig "forward/internal/config/tls"
	"forward/internal/dialer"
	hhttp "forward/internal/handler/http"
	"forward/internal/listener"
)

func init() {
	listener.Register("http", newRunner)
	listener.Register("https", newRunnerTLS)
	listener.Register("tls", newRunnerTLS)
}

func newRunner(cfg config.Config, d dialer.Dialer) (listener.Runner, error) {
	if !strings.EqualFold(cfg.Listen.Scheme, "http") {
		return nil, fmt.Errorf("http listener requires listen scheme http, got %s", cfg.Listen.Scheme)
	}

	h := hhttp.New(cfg, d)
	return New(cfg, h), nil
}

func newRunnerTLS(cfg config.Config, d dialer.Dialer) (listener.Runner, error) {
	if !strings.EqualFold(cfg.Listen.Scheme, "https") && !strings.EqualFold(cfg.Listen.Scheme, "tls") {
		return nil, fmt.Errorf("https listener requires listen scheme https/tls, got %s", cfg.Listen.Scheme)
	}

	tlsCfg, err := tlsconfig.ServerConfig(cfg, tlsconfig.ServerOptions{
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil, err
	}

	h := hhttp.New(cfg, d)
	return NewWithTLS(cfg, h, tlsCfg), nil
}
