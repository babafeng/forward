package router

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"

	"forward/base/endpoint"
	"forward/base/route"
	"forward/internal/chain"
)

type stubTransport struct{}

func (t *stubTransport) Dial(context.Context, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (t *stubTransport) Handshake(_ context.Context, conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (t *stubTransport) Connect(_ context.Context, conn net.Conn, _, _ string) (net.Conn, error) {
	return conn, nil
}

func (t *stubTransport) Copy() chain.Transporter {
	return t
}

func singleHopRoute(name string) chain.Route {
	node := chain.NewNode(name, name, &stubTransport{})
	node.Display = name
	return chain.NewRoute(node)
}

func TestStoreRouterRouteProxyChain(t *testing.T) {
	ep1, err := endpoint.Parse("socks5://127.0.0.1:1081")
	if err != nil {
		t.Fatalf("parse endpoint 1: %v", err)
	}
	ep2, err := endpoint.Parse("socks5://127.0.0.1:1082")
	if err != nil {
		t.Fatalf("parse endpoint 2: %v", err)
	}

	store, err := route.NewStore(&route.Config{
		Proxies: map[string]endpoint.Endpoint{
			"PROXY_1": ep1,
			"PROXY_2": ep2,
		},
		Rules: []route.Rule{
			{
				Type:  route.RuleDomain,
				Value: "ipconfig.me",
				Action: route.Action{
					Type:       route.ActionProxy,
					Proxy:      "PROXY_1",
					ProxyChain: []string{"PROXY_1", "PROXY_2"},
				},
			},
			{
				Type:   route.RuleFinal,
				Action: route.Action{Type: route.ActionDirect},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("new route store: %v", err)
	}

	rt := NewStore(store, chain.NewRoute(), map[string]chain.Route{
		"PROXY_1": singleHopRoute("PROXY_1"),
		"PROXY_2": singleHopRoute("PROXY_2"),
	})

	got, err := rt.Route(context.Background(), "tcp", "ipconfig.me:443")
	if err != nil {
		t.Fatalf("Route returned error: %v", err)
	}

	nodes := got.Nodes()
	if len(nodes) != 2 {
		t.Fatalf("node length = %d, want 2", len(nodes))
	}
	if nodes[0].Display != "PROXY_1" {
		t.Fatalf("node[0].Display = %s, want PROXY_1", nodes[0].Display)
	}
	if nodes[1].Display != "PROXY_2" {
		t.Fatalf("node[1].Display = %s, want PROXY_2", nodes[1].Display)
	}
}

func TestStoreRouterProxyBuilderRefreshesOnStoreUpdate(t *testing.T) {
	store, err := route.NewStore(&route.Config{
		Proxies: map[string]endpoint.Endpoint{
			"P1": mustParseEndpoint(t, "socks5://127.0.0.1:1080"),
		},
		Rules: []route.Rule{
			{
				Type:  route.RuleDomain,
				Value: "example.com",
				Action: route.Action{
					Type:  route.ActionProxy,
					Proxy: "P1",
				},
			},
			{
				Type:   route.RuleFinal,
				Action: route.Action{Type: route.ActionDirect},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("new route store: %v", err)
	}

	rt := NewStore(store, chain.NewRoute(), nil)
	buildCount := 0
	rt.SetProxyBuilder(func(name string) (chain.Route, error) {
		buildCount++
		return singleHopRoute(name + "-" + strconv.Itoa(buildCount)), nil
	})

	first, err := rt.Route(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("first route error: %v", err)
	}
	if got := first.Nodes()[0].Display; got != "P1-1" {
		t.Fatalf("first route display = %s, want P1-1", got)
	}

	if err := store.Update(&route.Config{
		Proxies: map[string]endpoint.Endpoint{
			"P1": mustParseEndpoint(t, "socks5://127.0.0.1:1081"),
		},
		Rules: []route.Rule{
			{
				Type:  route.RuleDomain,
				Value: "example.com",
				Action: route.Action{
					Type:  route.ActionProxy,
					Proxy: "P1",
				},
			},
			{
				Type:   route.RuleFinal,
				Action: route.Action{Type: route.ActionDirect},
			},
		},
	}, nil); err != nil {
		t.Fatalf("update route store: %v", err)
	}

	second, err := rt.Route(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("second route error: %v", err)
	}
	if got := second.Nodes()[0].Display; got != "P1-2" {
		t.Fatalf("second route display = %s, want P1-2", got)
	}
	if buildCount != 2 {
		t.Fatalf("build count = %d, want 2", buildCount)
	}
}

func mustParseEndpoint(t *testing.T, raw string) endpoint.Endpoint {
	t.Helper()
	ep, err := endpoint.Parse(raw)
	if err != nil {
		t.Fatalf("parse endpoint %s: %v", raw, err)
	}
	return ep
}
