package reverse

import (
	"fmt"
	"strings"

	"forward/internal/config"
	"forward/internal/dialer"
	hrev "forward/internal/handler/reverse"
	"forward/internal/listener"
)

func init() {
	listener.Register("reverse", newRunner)
}

func newRunner(cfg config.Config, d dialer.Dialer) (listener.Runner, error) {
	if cfg.Listen.Query.Get("bind") != "true" {
		return nil, fmt.Errorf("reverse listener requires bind=true")
	}
	scheme := strings.ToLower(cfg.Listen.Scheme)
	if scheme != "tls" && scheme != "quic" && scheme != "http3" && scheme != "https" {
		return nil, fmt.Errorf("reverse listener supports tcp/tls/https/quic/http3, got %s", cfg.Listen.Scheme)
	}
	h, err := hrev.NewServer(cfg)
	if err != nil {
		return nil, err
	}
	return New(cfg, h)
}
