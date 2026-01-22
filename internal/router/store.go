package router

import (
	"context"
	"fmt"
	"strings"

	"forward/internal/chain"
	"forward/base/route"
)

type StoreRouter struct {
	store        *route.Store
	defaultRoute chain.Route
	proxies      map[string]chain.Route
}

func NewStore(store *route.Store, defaultRoute chain.Route, proxies map[string]chain.Route) *StoreRouter {
	return &StoreRouter{
		store:        store,
		defaultRoute: defaultRoute,
		proxies:      proxies,
	}
}

func (r *StoreRouter) Route(ctx context.Context, network, address string) (chain.Route, error) {
	if r == nil || r.store == nil {
		return r.fallback(), nil
	}
	decision, err := r.store.Decide(ctx, address)
	if err != nil {
		return r.fallback(), err
	}
	via := strings.ToUpper(strings.TrimSpace(decision.Via))
	switch via {
	case "", "DIRECT":
		return r.fallback(), nil
	case "REJECT":
		return nil, fmt.Errorf("route rejected")
	default:
		if r.proxies != nil {
			if rt, ok := r.proxies[route.NormalizeProxyName(via)]; ok {
				return rt, nil
			}
		}
		return r.fallback(), fmt.Errorf("unknown proxy %s", via)
	}
}

func (r *StoreRouter) fallback() chain.Route {
	if r != nil && r.defaultRoute != nil {
		return r.defaultRoute
	}
	return chain.NewRoute()
}
