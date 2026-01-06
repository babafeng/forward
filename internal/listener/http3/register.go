package http3

import (
	"fmt"
	"strings"

	"github.com/quic-go/quic-go/http3"

	"forward/internal/config"
	tlsconfig "forward/internal/config/tls"
	"forward/internal/dialer"
	hhttp "forward/internal/handler/http"
	"forward/internal/listener"
)

func init() {
	listener.Register("http3", newRunner)
	listener.Register("quic", newRunner)
}

func newRunner(cfg config.Config, d dialer.Dialer) (listener.Runner, error) {
	if !strings.EqualFold(cfg.Listen.Scheme, "http3") && !strings.EqualFold(cfg.Listen.Scheme, "quic") {
		return nil, fmt.Errorf("http3 listener requires listen scheme http3/quic, got %s", cfg.Listen.Scheme)
	}

	tlsCfg, err := tlsconfig.ServerConfig(cfg, tlsconfig.ServerOptions{
		NextProtos: []string{"h3"},
	})
	if err != nil {
		return nil, err
	}

	h := hhttp.New(cfg, d)

	server := &http3.Server{
		TLSConfig: http3.ConfigureTLSConfig(tlsCfg),
		Handler:   h,
	}

	return New(cfg, h, server), nil
}
