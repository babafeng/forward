package router

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"forward/base/endpoint"
	"forward/base/logging"
	"forward/base/route"
	"forward/internal/chain"
	ictx "forward/internal/ctx"
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

type failTransport struct{}

func (t *failTransport) Dial(context.Context, string) (net.Conn, error) {
	return nil, errors.New("dial failed")
}

func (t *failTransport) Handshake(_ context.Context, conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (t *failTransport) Connect(_ context.Context, _ net.Conn, _, _ string) (net.Conn, error) {
	return nil, errors.New("connect failed")
}

func (t *failTransport) Copy() chain.Transporter {
	return t
}

func singleHopRoute(name string) chain.Route {
	node := chain.NewNode(name, name, &stubTransport{})
	node.Display = name
	return chain.NewRoute(node)
}

type closableRoute struct {
	nodes  []*chain.Node
	closed atomic.Int32
}

func newClosableRoute(name string) *closableRoute {
	node := chain.NewNode(name, name, &stubTransport{})
	node.Display = name
	return &closableRoute{nodes: []*chain.Node{node}}
}

func (r *closableRoute) Dial(_ context.Context, _ string, _ string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (r *closableRoute) Nodes() []*chain.Node {
	return r.nodes
}

func (r *closableRoute) Close() {
	r.closed.Add(1)
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
	var built []*closableRoute
	rt.SetProxyBuilder(func(name string) (chain.Route, error) {
		buildCount++
		route := newClosableRoute(name + "-" + strconv.Itoa(buildCount))
		built = append(built, route)
		return route, nil
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
	if got := built[0].closed.Load(); got != 1 {
		t.Fatalf("first built route close count = %d, want 1", got)
	}
	if got := built[1].closed.Load(); got != 0 {
		t.Fatalf("second built route close count = %d, want 0", got)
	}
}

func TestStoreRouterDoesNotPrefixBalancerOntoProxyRouteByDefault(t *testing.T) {
	store, err := route.NewStore(&route.Config{
		Proxies: map[string]endpoint.Endpoint{
			"PROXY_HK_01": mustParseEndpoint(t, "socks5://1.2.3.4:443"),
		},
		Rules: []route.Rule{
			{
				Type: route.RuleFinal,
				Action: route.Action{
					Type:  route.ActionProxy,
					Proxy: "PROXY_HK_01",
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("new route store: %v", err)
	}

	subNode := chain.NewNode("sub", "127.0.0.1:1", &successTransport{})
	subNode.Display = "香港 | V1 | 05"
	defaultRoute := chain.NewBalancerRouteWithCandidates([]chain.BalancerCandidate{
		{
			Node:  subNode,
			Route: chain.NewRoute(subNode),
		},
	}, time.Hour, 30*time.Millisecond)
	defer defaultRoute.Close()

	rt := NewStore(store, defaultRoute, nil)
	rt.SetProxyBuilder(func(name string) (chain.Route, error) {
		node := chain.NewNode(name, "1.2.3.4:443", &successTransport{})
		return chain.NewRoute(node), nil
	})

	var out bytes.Buffer
	logger := logging.New(logging.Options{
		Level: logging.LevelInfo,
		Out:   &out,
		Err:   &out,
	})
	traceCtx := ictx.ContextWithTrace(context.Background(), &ictx.Trace{
		Src:    "192.168.1.224:51666",
		Local:  "1.2.3.4:80",
		Logger: logger,
	})

	got, err := rt.Route(context.Background(), "tcp", "szextshort.weixin.qq.com:80")
	if err != nil {
		t.Fatalf("Route returned error: %v", err)
	}

	conn, err := got.Dial(traceCtx, "tcp", "szextshort.weixin.qq.com:80")
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	_ = conn.Close()

	logs := out.String()
	if !strings.Contains(logs, "via PROXY_HK_01(1.2.3.4:443)") {
		t.Fatalf("log missing proxy-only route summary, got: %s", logs)
	}
	if strings.Contains(logs, "[香港 | V1 | 05] -> PROXY_HK_01") {
		t.Fatalf("log should not include subscription prefix by default, got: %s", logs)
	}
}

func TestStoreRouterPrefixesBalancerOntoProxyRouteWhenExplicitlyRequested(t *testing.T) {
	store, err := route.NewStore(&route.Config{
		Proxies: map[string]endpoint.Endpoint{
			"PROXY_HK_01": mustParseEndpoint(t, "socks5://1.2.3.4:443"),
		},
		Rules: []route.Rule{
			{
				Type: route.RuleFinal,
				Action: route.Action{
					Type:         route.ActionProxy,
					Proxy:        "PROXY_HK_01",
					UseSubscribe: true,
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("new route store: %v", err)
	}

	subNode := chain.NewNode("sub", "127.0.0.1:1", &successTransport{})
	subNode.Display = "香港 | V1 | 05"
	defaultRoute := chain.NewBalancerRouteWithCandidates([]chain.BalancerCandidate{
		{
			Node:  subNode,
			Route: chain.NewRoute(subNode),
		},
	}, time.Hour, 30*time.Millisecond)
	defer defaultRoute.Close()

	rt := NewStore(store, defaultRoute, nil)
	rt.SetProxyBuilder(func(name string) (chain.Route, error) {
		node := chain.NewNode(name, "1.2.3.4:443", &successTransport{})
		return chain.NewRoute(node), nil
	})

	var out bytes.Buffer
	logger := logging.New(logging.Options{
		Level: logging.LevelInfo,
		Out:   &out,
		Err:   &out,
	})
	traceCtx := ictx.ContextWithTrace(context.Background(), &ictx.Trace{
		Src:    "192.168.1.224:51666",
		Local:  "1.2.3.4:80",
		Logger: logger,
	})

	got, err := rt.Route(context.Background(), "tcp", "szextshort.weixin.qq.com:80")
	if err != nil {
		t.Fatalf("Route returned error: %v", err)
	}

	conn, err := got.Dial(traceCtx, "tcp", "szextshort.weixin.qq.com:80")
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	_ = conn.Close()

	logs := out.String()
	if !strings.Contains(logs, "via [香港 | V1 | 05] -> PROXY_HK_01(1.2.3.4:443)") {
		t.Fatalf("log missing composed route summary, got: %s", logs)
	}
}

func TestStoreRouterExplicitDirectBypassesBalancerFallback(t *testing.T) {
	store, err := route.NewStore(&route.Config{
		Rules: []route.Rule{
			{
				Type:   route.RuleFinal,
				Action: route.Action{Type: route.ActionDirect},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("new route store: %v", err)
	}

	subNode := chain.NewNode("sub", "127.0.0.1:1", &successTransport{})
	subNode.Display = "香港 | V1 | 05"
	defaultRoute := chain.NewBalancerRouteWithCandidates([]chain.BalancerCandidate{
		{
			Node:  subNode,
			Route: chain.NewRoute(subNode),
		},
	}, time.Hour, 30*time.Millisecond)
	defer defaultRoute.Close()

	rt := NewStore(store, defaultRoute, nil)

	got, err := rt.Route(context.Background(), "tcp", "api5-normal-sinfonlinec.fqnovel.com:443")
	if err != nil {
		t.Fatalf("Route returned error: %v", err)
	}
	if summary := chain.RouteSummary(got); summary != "DIRECT" {
		t.Fatalf("RouteSummary = %q, want DIRECT", summary)
	}
	if got.Nodes() != nil {
		t.Fatalf("Nodes() = %v, want nil for direct route", got.Nodes())
	}
}

func TestStoreRouterFallsBackToProxyWhenBalancerRetestMarksAllFailed(t *testing.T) {
	store, err := route.NewStore(&route.Config{
		Proxies: map[string]endpoint.Endpoint{
			"PROXY_HK_01": mustParseEndpoint(t, "socks5://1.2.3.4:443"),
		},
		Rules: []route.Rule{
			{
				Type: route.RuleFinal,
				Action: route.Action{
					Type:         route.ActionProxy,
					Proxy:        "PROXY_HK_01",
					UseSubscribe: true,
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("new route store: %v", err)
	}

	subNode := chain.NewNode("sub", "127.0.0.1:1", &failTransport{})
	subNode.Display = "香港 | V1 | 05"
	defaultRoute := chain.NewBalancerRouteWithCandidates([]chain.BalancerCandidate{
		{
			Node:  subNode,
			Route: chain.NewRoute(subNode),
		},
	}, time.Hour, 30*time.Millisecond)
	defer defaultRoute.Close()

	deadline := time.Now().Add(time.Second)
	for !defaultRoute.AllFailed() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !defaultRoute.AllFailed() {
		t.Fatal("AllFailed = false, want true after background retest marks every candidate unavailable")
	}

	rt := NewStore(store, defaultRoute, nil)
	rt.SetProxyBuilder(func(name string) (chain.Route, error) {
		node := chain.NewNode(name, "1.2.3.4:443", &successTransport{})
		return chain.NewRoute(node), nil
	})

	var out bytes.Buffer
	logger := logging.New(logging.Options{
		Level: logging.LevelInfo,
		Out:   &out,
		Err:   &out,
	})
	traceCtx := ictx.ContextWithTrace(context.Background(), &ictx.Trace{
		Src:    "192.168.1.224:33612",
		Local:  "1.2.3.4:443",
		Logger: logger,
	})

	got, err := rt.Route(context.Background(), "tcp", "android.googleapis.com:443")
	if err != nil {
		t.Fatalf("Route returned error: %v", err)
	}

	conn, err := got.Dial(traceCtx, "tcp", "android.googleapis.com:443")
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	_ = conn.Close()

	logs := out.String()
	if !strings.Contains(logs, "via PROXY_HK_01(1.2.3.4:443)") {
		t.Fatalf("log missing proxy-only fallback summary, got: %s", logs)
	}
	if strings.Contains(logs, "[香港 | V1 | 05] -> PROXY_HK_01") {
		t.Fatalf("log should bypass subscription prefix after fallback, got: %s", logs)
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

type successTransport struct{}

func (t *successTransport) Dial(context.Context, string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

func (t *successTransport) Handshake(_ context.Context, conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (t *successTransport) Connect(_ context.Context, conn net.Conn, _, _ string) (net.Conn, error) {
	return conn, nil
}

func (t *successTransport) Copy() chain.Transporter {
	return t
}
