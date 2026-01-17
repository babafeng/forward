package dialer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"forward/internal/config"
	"forward/internal/endpoint"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Factory func(cfg config.Config) (Dialer, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

func Register(scheme string, f Factory) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" || f == nil {
		panic("dialer: Register requires non-empty scheme and non-nil factory")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, exists := factories[scheme]; exists {
		panic("dialer: duplicate register for scheme: " + scheme)
	}
	factories[scheme] = f
}

func New(cfg config.Config) (Dialer, error) {
	if cfg.Mode == config.ModePortForward {
		if cfg.Forward != nil {
			scheme := strings.ToLower(cfg.Forward.Scheme)
			if scheme != "tcp" && scheme != "udp" {
				return newDialerWithForward(cfg, *cfg.Forward)
			}
		}

		return NewDirect(cfg), nil
	}

	if cfg.RouteStore != nil {
		return NewRouteDialer(cfg, cfg.RouteStore)
	}

	if cfg.Forward == nil {
		return NewDirect(cfg), nil
	}

	return newDialerWithForward(cfg, *cfg.Forward)
}

func newDialerWithForward(cfg config.Config, forward endpoint.Endpoint) (Dialer, error) {
	scheme := strings.ToLower(forward.Scheme)
	mu.RLock()
	f, ok := factories[scheme]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unsupported forward scheme: %s", forward.Scheme)
	}
	cfg.Forward = &forward
	cfg.Route = nil
	cfg.RouteStore = nil
	return f(cfg)
}

type Direct struct {
	d net.Dialer
}

func NewNetDialer(cfg config.Config) *net.Dialer {
	timeout := cfg.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	keepAlive := cfg.DialKeepAlive
	if keepAlive == 0 {
		keepAlive = 30 * time.Second
	}
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: keepAlive,
	}
}

func NewDirect(cfg config.Config) *Direct {
	return &Direct{
		d: *NewNetDialer(cfg),
	}
}

func (d *Direct) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.d.DialContext(ctx, network, address)
}
