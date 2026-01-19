package http3

import (
	"fmt"
	"strings"

	"github.com/quic-go/quic-go/http3"

	"forward/inner/config"
	tlsconfig "forward/inner/config/tls"
	"forward/inner/dialer"
	hhttp "forward/inner/handler/http"
	"forward/inner/listener"
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

	maxHeaderBytes := cfg.MaxHeaderBytes
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = config.DefaultMaxHeaderBytes
	}

	server := &http3.Server{
		TLSConfig:      http3.ConfigureTLSConfig(tlsCfg),
		Handler:        h,
		MaxHeaderBytes: maxHeaderBytes,
	}

	return New(cfg, h, server), nil
}
