package app

import (
	"fmt"
	"strings"
	"time"

	"forward/base/endpoint"
	"forward/base/route"
	"forward/internal/builder"
	"forward/internal/chain"
	"forward/internal/config"
	"forward/internal/router"
	schememap "forward/internal/scheme"
	"forward/internal/subscribe"
)

func buildRouter(cfg config.Config) (router.Router, error) {
	var hops []endpoint.Endpoint
	if len(cfg.ForwardChain) > 0 {
		hops = cfg.ForwardChain
	} else if cfg.Forward != nil {
		hops = []endpoint.Endpoint{*cfg.Forward}
	}

	var defaultRoute chain.Route
	subscribeURLs := cfg.EffectiveSubscribeURLs()
	if len(subscribeURLs) > 0 {
		subNodes, subCandidates, err := fetchAndBuildSubCandidates(cfg, hops)
		if err != nil {
			return nil, err
		}

		if len(hops) > 0 {
			defaultRoute = chain.NewBalancerRouteWithCandidates(subCandidates, 2*time.Minute, cfg.DialTimeout)
		} else {
			defaultRoute = chain.NewBalancerRoute(subNodes, 2*time.Minute, cfg.DialTimeout)
		}

		// 注册紧急回调：全部节点失败时立刻重新拉取订阅并热更新 (节流 5 分钟)
		br := defaultRoute.(*chain.BalancerRoute)
		if len(hops) > 0 {
			fallbackRoute, err := builder.BuildRoutePooled(cfg, hops)
			if err != nil {
				return nil, err
			}
			br.SetFallbackRoute(fallbackRoute)
		}
		emergencyCfg := cfg
		emergencyHops := hops
		br.SetOnAllFailed(func() {
			if emergencyCfg.Logger != nil {
				emergencyCfg.Logger.Warn("All nodes failed, emergency re-fetching subscriptions")
			}
			newNodes, newCandidates, err := fetchAndBuildSubCandidates(emergencyCfg, emergencyHops)
			if err != nil {
				if emergencyCfg.Logger != nil {
					emergencyCfg.Logger.Error("Emergency subscription refresh failed: %v", err)
				}
				return
			}
			if len(emergencyHops) > 0 {
				br.UpdateCandidates(newCandidates)
			} else {
				cands := make([]chain.BalancerCandidate, 0, len(newNodes))
				for _, n := range newNodes {
					cands = append(cands, chain.BalancerCandidate{Node: n})
				}
				br.UpdateCandidates(cands)
			}
			if emergencyCfg.Logger != nil {
				emergencyCfg.Logger.Info("Emergency subscription refresh completed, loaded %d nodes", len(newCandidates))
			}
		})

		// Start background update loop if enabled
		if cfg.SubscribeUpdate > 0 {
			go subscribeUpdateLoop(cfg, hops, subscribeURLs, br)
		}
	} else if len(hops) > 0 {
		rt, err := builder.BuildRoutePooled(cfg, hops)
		if err != nil {
			return nil, err
		}
		defaultRoute = rt
	} else {
		defaultRoute = chain.NewRouteWithTimeout(cfg.DialTimeout)
	}

	if cfg.Route == nil {
		return router.NewStatic(defaultRoute), nil
	}

	store := cfg.RouteStore
	if store == nil {
		rstore, err := route.NewStore(cfg.Route, cfg.Logger)
		if err != nil {
			return nil, err
		}
		store = rstore
	}

	buildProxyRoute := func(name string) (chain.Route, error) {
		ep, ok := store.GetProxy(name)
		if !ok {
			return nil, fmt.Errorf("unknown proxy %s", name)
		}
		rt, err := builder.BuildRoutePooled(cfg, []endpoint.Endpoint{ep})
		if err != nil {
			return nil, err
		}
		nodes := rt.Nodes()
		if len(nodes) > 0 && nodes[0] != nil {
			nodes[0].Name = name
			nodes[0].Display = ""
		}
		return rt, nil
	}

	sr := router.NewStore(store, defaultRoute, nil)
	sr.SetProxyBuilder(buildProxyRoute)
	return sr, nil
}

func fetchAndBuildSubCandidates(cfg config.Config, hops []endpoint.Endpoint) ([]*chain.Node, []chain.BalancerCandidate, error) {
	proxies, err := loadSubscribeProxies(cfg.EffectiveSubscribeURLs(), cfg.Logger)
	if err != nil {
		return nil, nil, err
	}
	if cfg.SubscribeFilter != "" {
		proxies = subscribe.FilterProxies(proxies, cfg.SubscribeFilter)
	}
	proxies = dedupeSubscribeProxies(proxies)
	if len(proxies) == 0 {
		return nil, nil, fmt.Errorf("no matching nodes in subscription")
	}
	// Keep subscription startup bounded: pre-warming hundreds of candidates
	// creates significant background dials. Use pooled routes only for a
	// moderate candidate set.
	usePooled := len(proxies) <= 32

	var subNodes []*chain.Node
	var subCandidates []chain.BalancerCandidate
	for _, proxy := range proxies {
		ep, err := subscribe.ProxyToEndpoint(proxy)
		if err != nil {
			continue
		}

		routeHops := make([]endpoint.Endpoint, 0, 1+len(hops))
		routeHops = append(routeHops, ep)
		routeHops = append(routeHops, hops...)

		var rt chain.Route
		if usePooled {
			rt, err = builder.BuildRoutePooled(cfg, routeHops)
		} else {
			rt, err = builder.BuildRoute(cfg, routeHops)
		}
		if err != nil {
			continue
		}
		nodes := rt.Nodes()
		if len(nodes) > 0 {
			nodes[0].Display = proxy.Name
			subNodes = append(subNodes, nodes[0])
			subCandidates = append(subCandidates, chain.BalancerCandidate{
				Node:  nodes[0],
				Route: rt,
			})
		}
	}

	if len(subCandidates) == 0 {
		return nil, nil, fmt.Errorf("no valid matching nodes in subscription")
	}

	if cfg.Logger != nil {
		if len(hops) > 0 {
			cfg.Logger.Info("Built balancer route with %d nodes from subscriptions and %d fixed forward hop(s)", len(subCandidates), len(hops))
		} else {
			cfg.Logger.Info("Built balancer route with %d nodes from subscriptions", len(subCandidates))
		}
	}

	return subNodes, subCandidates, nil
}

func isProxyServer(scheme string) bool {
	base, transport := splitSchemeTransport(scheme)
	if base == "http2" || base == "http3" {
		return transport == transportNone
	}
	if base == "vless" {
		return true
	}
	if base == "vmess" {
		return true
	}
	if base == "hysteria2" || base == "hy2" {
		return true
	}
	if base == "ss" || base == "shadowsocks" {
		return true
	}
	switch base {
	case "http", "socks5", "socks5h", "tproxy":
		return true
	default:
		return false
	}
}

func isReverseServer(cfg config.Config) bool {
	if cfg.Listen.Query.Get("bind") != "true" {
		return false
	}
	switch strings.ToLower(cfg.Listen.Scheme) {
	case "tls", "https", "http3", "quic", "reality", "vless+reality":
		return true
	default:
		return false
	}
}

func isReverseClient(cfg config.Config) bool {
	ls := strings.ToLower(cfg.Listen.Scheme)
	if ls != "rtcp" && ls != "rudp" {
		return false
	}
	if cfg.Listen.FAddress == "" {
		return false
	}
	if cfg.Forward == nil && len(cfg.ForwardChain) == 0 {
		return false
	}
	return true
}

func isPortForward(cfg config.Config) bool {
	ls, transport := splitSchemeTransport(cfg.Listen.Scheme)
	if ls != "tcp" && ls != "udp" {
		return false
	}
	if ls == "udp" && transport != transportNone {
		return false
	}
	if cfg.Forward == nil {
		return cfg.Listen.FAddress != ""
	}
	fs, _ := splitSchemeTransport(cfg.Forward.Scheme)
	return strings.EqualFold(ls, fs)
}

type transportKind = schememap.TransportKind

const (
	transportNone = schememap.TransportNone
	transportTLS  = schememap.TransportTLS
	transportDTLS = schememap.TransportDTLS
	transportH2   = schememap.TransportH2
	transportH3   = schememap.TransportH3
	transportQuic = schememap.TransportQUIC
)

func splitSchemeTransport(scheme string) (base string, transport transportKind) {
	return schememap.SplitTransport(scheme)
}

func normalizeProxySchemes(scheme string) (handlerScheme, listenerScheme string, transport transportKind) {
	types := schememap.NormalizeProxy(scheme)
	return types.Handler, types.Listener, types.Transport
}
