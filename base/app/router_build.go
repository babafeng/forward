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
		for _, node := range rt.Nodes() {
			if node != nil {
				node.Display = name
			}
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

type transportKind string

const (
	transportNone transportKind = ""
	transportTLS  transportKind = "tls"
	transportDTLS transportKind = "dtls"
	transportH2   transportKind = "h2"
	transportH3   transportKind = "h3"
)

func splitSchemeTransport(scheme string) (base string, transport transportKind) {
	s := strings.ToLower(strings.TrimSpace(scheme))
	switch s {
	case "https":
		return "http", transportTLS
	case "http2":
		return "http2", transportNone
	case "http3":
		return "http3", transportNone
	case "tls":
		return "http", transportTLS
	case "h2":
		return "http", transportH2
	case "h3":
		return "http", transportH3
	case "dtls":
		return "tcp", transportDTLS
	case "hysteria2", "hy2":
		return "hysteria2", transportNone
	// VLESS + Reality
	case "vless", "vless+reality", "reality":
		return "vless", transportNone
	case "vless+tls":
		return "vless", transportTLS
	// VMess
	case "vmess":
		return "vmess", transportNone
	case "vmess+tls":
		return "vmess", transportTLS
	}
	if strings.HasSuffix(s, "+h2") {
		return strings.TrimSuffix(s, "+h2"), transportH2
	}
	if strings.HasSuffix(s, "+h3") {
		return strings.TrimSuffix(s, "+h3"), transportH3
	}
	if strings.HasSuffix(s, "+tls") {
		return strings.TrimSuffix(s, "+tls"), transportTLS
	}
	if strings.HasSuffix(s, "+dtls") {
		return strings.TrimSuffix(s, "+dtls"), transportDTLS
	}
	// VLESS + Reality 带后缀
	if strings.HasSuffix(s, "+reality") {
		return strings.TrimSuffix(s, "+reality"), transportNone
	}
	return s, transportNone
}

func normalizeProxySchemes(scheme string) (handlerScheme, listenerScheme string, transport transportKind) {
	base, transport := splitSchemeTransport(scheme)
	handlerScheme = base
	listenerScheme = base

	switch base {
	case "http3":
		handlerScheme = "http"
		listenerScheme = "http3"
		return handlerScheme, listenerScheme, transportNone
	case "http2":
		handlerScheme = "http"
		listenerScheme = "http2"
		return handlerScheme, listenerScheme, transportNone
	case "socks5h":
		handlerScheme = "socks5"
	// VLESS + Reality
	case "vless":
		handlerScheme = "vless"
		listenerScheme = "reality"
		return handlerScheme, listenerScheme, transportNone
	// VMess
	case "vmess":
		handlerScheme = "vmess"
		listenerScheme = "tcp" // VMess 使用普通 TCP 监听
	// Shadowsocks
	case "ss", "shadowsocks":
		handlerScheme = "ss"
		listenerScheme = "tcp" // SS 使用普通 TCP 监听
	}

	if transport == transportDTLS {
		listenerScheme = "dtls"
	}
	if transport == transportH2 {
		listenerScheme = "h2"
	}
	if transport == transportH3 {
		listenerScheme = "h3"
	}
	return
}
