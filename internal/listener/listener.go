package listener

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"forward/internal/config"
	"forward/internal/dialer"
)

type Runner interface {
	Run(ctx context.Context) error
}

type Factory func(cfg config.Config, d dialer.Dialer) (Runner, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

func Register(scheme string, f Factory) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" || f == nil {
		panic("listener: Register requires non-empty scheme and non-nil factory")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, exists := factories[scheme]; exists {
		panic("listener: duplicate register for scheme: " + scheme)
	}
	factories[scheme] = f
}

func New(cfg config.Config, d dialer.Dialer) (Runner, error) {
	scheme := strings.ToLower(cfg.Listen.Scheme)

	mu.RLock()
	var f Factory
	var ok bool

	if cfg.IsReverseServer {
		f, ok = factories["reverse"]
	} else {
		f, ok = factories[scheme]
	}

	mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unsupported listen scheme: %s", cfg.Listen.Scheme)
	}
	return f(cfg, d)
}
