package udp

import (
	"fmt"
	"strings"

	"forward/inner/config"
	"forward/inner/dialer"
	hudp "forward/inner/handler/udp"
	"forward/inner/listener"
)

func init() {
	listener.Register("udp", newRunner)
}

func newRunner(cfg config.Config, d dialer.Dialer) (listener.Runner, error) {
	if cfg.Forward == nil {
		return nil, fmt.Errorf("udp listener requires forward endpoint")
	}
	if !strings.EqualFold(cfg.Listen.Scheme, "udp") {
		return nil, fmt.Errorf("udp listener requires listen scheme udp, got %s", cfg.Listen.Scheme)
	}
	if !strings.EqualFold(cfg.Forward.Scheme, "udp") {
		return nil, fmt.Errorf("udp listener requires forward scheme udp, got %s", cfg.Forward.Scheme)
	}

	h := hudp.New(cfg, d)
	return New(cfg, h), nil
}
