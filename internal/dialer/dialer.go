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

type BaseSetter interface {
	SetBase(Dialer)
}

type PacketDialer interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
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
		if len(cfg.ForwardChain) > 0 {
			return newDialerWithForwardChain(cfg, cfg.ForwardChain)
		}
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

	if len(cfg.ForwardChain) > 0 {
		return newDialerWithForwardChain(cfg, cfg.ForwardChain)
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

func newDialerWithForwardChain(cfg config.Config, chain []endpoint.Endpoint) (Dialer, error) {
	if len(chain) == 0 {
		return NewDirect(cfg), nil
	}

	base := Dialer(NewDirect(cfg))
	var current Dialer

	for i, hop := range chain {
		d, err := newDialerWithForward(cfg, hop)
		if err != nil {
			return nil, fmt.Errorf("forward chain hop %d (%s) init error: %w", i+1, hop.Scheme, err)
		}
		if i > 0 {
			if scheme := strings.ToLower(hop.Scheme); scheme == "quic" || scheme == "http3" {
				if _, ok := base.(PacketDialer); !ok {
					return nil, fmt.Errorf("forward chain hop %d (%s) requires UDP-capable base", i+1, hop.Scheme)
				}
			}
		}
		if i > 0 {
			setter, ok := d.(BaseSetter)
			if !ok {
				return nil, fmt.Errorf("forward chain hop %d (%s) does not support chaining", i+1, hop.Scheme)
			}
			setter.SetBase(base)
		}
		base = d
		current = d
	}

	return current, nil
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

func (d *Direct) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if address == "" {
		address = ":0"
	}
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, address)
}
