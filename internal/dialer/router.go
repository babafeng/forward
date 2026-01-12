package dialer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"forward/internal/config"
	"forward/internal/route"
)

type RouteDialer struct {
	baseCfg config.Config
	store   *route.Store
	direct  Dialer

	mu      sync.Mutex
	version uint64
	proxies map[string]Dialer
}

func NewRouteDialer(cfg config.Config, store *route.Store) (Dialer, error) {
	return &RouteDialer{
		baseCfg: cfg,
		store:   store,
		direct:  NewDirect(cfg),
		proxies: make(map[string]Dialer),
	}, nil
}

func (d *RouteDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil || d.direct == nil {
		return nil, fmt.Errorf("dialer not initialized")
	}
	return d.direct.DialContext(ctx, network, address)
}

func (d *RouteDialer) DialContextVia(ctx context.Context, network, address, via string) (net.Conn, error) {
	if d == nil {
		return nil, fmt.Errorf("dialer not initialized")
	}
	via = strings.ToUpper(strings.TrimSpace(via))
	switch via {
	case "", "DIRECT":
		return d.direct.DialContext(ctx, network, address)
	case "REJECT":
		return nil, fmt.Errorf("route rejected")
	default:
		target, err := d.proxyDialer(via)
		if err != nil {
			return nil, err
		}
		return target.DialContext(ctx, network, address)
	}
}

func (d *RouteDialer) proxyDialer(name string) (Dialer, error) {
	if d.store == nil {
		return nil, fmt.Errorf("route store not initialized")
	}
	version := d.store.Version()

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.version != version {
		d.proxies = make(map[string]Dialer)
		d.version = version
	}

	if p := d.proxies[name]; p != nil {
		return p, nil
	}

	ep, ok := d.store.GetProxy(name)
	if !ok {
		return nil, fmt.Errorf("unknown proxy %s", name)
	}

	proxyDialer, err := newDialerWithForward(d.baseCfg, ep)
	if err != nil {
		return nil, fmt.Errorf("create proxy dialer %s: %w", name, err)
	}
	d.proxies[name] = proxyDialer
	return proxyDialer, nil
}
