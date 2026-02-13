package router

import (
	"context"
	"fmt"
	"strings"

	"forward/base/route"
	"forward/internal/chain"
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
	names := normalizeDecisionChain(decision)
	if len(names) == 0 {
		return r.fallback(), nil
	}
	if len(names) == 1 && names[0] == "REJECT" {
		return nil, fmt.Errorf("route rejected")
	}

	if r.proxies == nil {
		return r.fallback(), fmt.Errorf("unknown proxy %s", strings.Join(names, " -> "))
	}

	if len(names) == 1 {
		if rt, ok := r.proxies[route.NormalizeProxyName(names[0])]; ok {
			return rt, nil
		}
		return r.fallback(), fmt.Errorf("unknown proxy %s", names[0])
	}

	nodes := make([]*chain.Node, 0, len(names))
	for _, name := range names {
		rt, ok := r.proxies[route.NormalizeProxyName(name)]
		if !ok {
			return r.fallback(), fmt.Errorf("unknown proxy %s", name)
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
