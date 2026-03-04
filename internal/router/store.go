package router

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"forward/base/route"
	"forward/internal/chain"
)

type StoreRouter struct {
	store        *route.Store
	defaultRoute chain.Route

	mu           sync.RWMutex
	proxies      map[string]proxyRoute
	proxyBuilder func(name string) (chain.Route, error)
}

type proxyRoute struct {
	route   chain.Route
	version uint64
}

func NewStore(store *route.Store, defaultRoute chain.Route, proxies map[string]chain.Route) *StoreRouter {
	cache := map[string]proxyRoute{}
	for name, rt := range proxies {
		normalized := route.NormalizeProxyName(name)
		if normalized == "" {
			continue
		}
		cache[normalized] = proxyRoute{route: rt}
	}
	return &StoreRouter{
		store:        store,
		defaultRoute: defaultRoute,
		proxies:      cache,
	}
}

func (r *StoreRouter) SetProxyBuilder(builder func(name string) (chain.Route, error)) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.proxyBuilder = builder
	r.mu.Unlock()
}

func (r *StoreRouter) Route(ctx context.Context, network, address string) (chain.Route, error) {
	if r == nil || r.store == nil {
		return r.fallback(), nil
	}
	decision, err := r.store.Decide(ctx, address)
	if err != nil {
		return r.fallback(), err
	}
	names := normalizeDecisionChain(decision)
	if len(names) == 0 {
		return r.fallback(), nil
	}
	if len(names) == 1 && names[0] == "REJECT" {
		return nil, fmt.Errorf("route rejected")
	}

	if len(names) == 1 {
		rt, err := r.resolveProxy(names[0])
		if err == nil {
			return rt, nil
		}
		return r.fallback(), err
	}

	nodes := make([]*chain.Node, 0, len(names))
	for _, name := range names {
		rt, err := r.resolveProxy(name)
		if err != nil {
			return r.fallback(), err
		}
		nodes = append(nodes, rt.Nodes()...)
	}
	if len(nodes) == 0 {
		return r.fallback(), nil
	}
	return chain.NewRoute(nodes...), nil
}

func (r *StoreRouter) fallback() chain.Route {
	if r != nil && r.defaultRoute != nil {
		return r.defaultRoute
	}
	return chain.NewRoute()
}

func (r *StoreRouter) resolveProxy(name string) (chain.Route, error) {
	if r == nil {
		return nil, fmt.Errorf("unknown proxy %s", name)
	}

	normalized := route.NormalizeProxyName(name)
	if normalized == "" {
		return nil, fmt.Errorf("unknown proxy %s", name)
	}

	version := uint64(0)
	if r.store != nil {
		version = r.store.Version()
	}

	r.mu.RLock()
	entry, ok := r.proxies[normalized]
	builder := r.proxyBuilder
	r.mu.RUnlock()
	if ok {
		// Without builder, keep legacy static behavior.
		if builder == nil || entry.version == version {
			return entry.route, nil
		}
	}

	if builder == nil {
		return nil, fmt.Errorf("unknown proxy %s", normalized)
	}

	rt, err := builder(normalized)
	if err != nil {
		return nil, fmt.Errorf("unknown proxy %s: %w", normalized, err)
	}
	if rt == nil {
		return nil, fmt.Errorf("unknown proxy %s", normalized)
	}

	r.mu.Lock()
	if r.proxies == nil {
		r.proxies = map[string]proxyRoute{}
	}
	r.proxies[normalized] = proxyRoute{route: rt, version: version}
	r.mu.Unlock()
	return rt, nil
}

func normalizeDecisionChain(decision route.Decision) []string {
	if len(decision.Chain) > 0 {
		out := make([]string, 0, len(decision.Chain))
		for _, name := range decision.Chain {
			normalized := strings.ToUpper(strings.TrimSpace(name))
			if normalized != "" {
				out = append(out, normalized)
			}
		}
		return out
	}

	via := strings.ToUpper(strings.TrimSpace(decision.Via))
	switch via {
	case "", "DIRECT":
		return nil
	case "REJECT":
		return []string{"REJECT"}
	default:
		return []string{via}
	}
}
