package router

import (
	"context"
	"errors"
	"net"
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
