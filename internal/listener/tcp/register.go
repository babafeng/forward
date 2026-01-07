package tcp

import (
	"fmt"
	"strings"

	"forward/internal/config"
	"forward/internal/dialer"
	htcp "forward/internal/handler/tcp"
	"forward/internal/listener"
)

func init() {
	listener.Register("tcp", newRunner)
}

func newRunner(cfg config.Config, d dialer.Dialer) (listener.Runner, error) {
	if cfg.Forward == nil {
		return nil, fmt.Errorf("tcp listener requires forward endpoint")
	}
	if !strings.EqualFold(cfg.Listen.Scheme, "tcp") {
		return nil, fmt.Errorf("tcp listener requires listen scheme tcp, got %s", cfg.Listen.Scheme)
	}
	if !strings.EqualFold(cfg.Forward.Scheme, "tcp") {
		return nil, fmt.Errorf("tcp listener requires forward scheme tcp, got %s", cfg.Forward.Scheme)
	}

	h := htcp.New(cfg, d)
	return New(cfg, h), nil
}
