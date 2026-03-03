package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"forward/base/endpoint"
	"forward/internal/chain"
	"forward/internal/config"
)

func TestBuildRouterSubscribeWithForwardChainUsesForwardHops(t *testing.T) {
	stubSubscribeDownload(t, `
proxies:
  - name: "日本-VMess"
    type: vmess
    server: 127.0.0.1
    port: 10086
    uuid: "11111111-1111-1111-1111-111111111111"
    alterId: 0
    cipher: auto
`)

	baseCfg := config.Config{
		SubscribeURL:    "https://sub.example.com/api",
		SubscribeFilter: "日本",
		DialTimeout:     50 * time.Millisecond,
	}

	if _, err := buildRouter(baseCfg); err != nil {
		t.Fatalf("buildRouter should succeed without forward chain, got: %v", err)
	}

	cfg := baseCfg
	cfg.ForwardChain = []endpoint.Endpoint{
		{
			Scheme: "not-supported",
			Host:   "jp.proxy.com",
			Port:   443,
		},
	}

	_, err := buildRouter(cfg)
	if err == nil {
		t.Fatalf("buildRouter should fail when subscribe route is chained with invalid forward hop")
	}
	if !strings.Contains(err.Error(), "no valid matching nodes in subscription") {
		t.Fatalf("buildRouter error = %v, want no valid matching nodes in subscription", err)
	}
}

func TestBuildRouterSubscribeWithForwardChainAndFilter(t *testing.T) {
	stubSubscribeDownload(t, `
proxies:
  - name: "日本-VMess"
    type: vmess
    server: 127.0.0.1
    port: 10086
    uuid: "11111111-1111-1111-1111-111111111111"
    alterId: 0
    cipher: auto
  - name: "US-VMess"
    type: vmess
    server: 127.0.0.1
    port: 10087
    uuid: "22222222-2222-2222-2222-222222222222"
    alterId: 0
    cipher: auto
`)

	forward, err := endpoint.Parse("https://jp.proxy.com:443")
	if err != nil {
		t.Fatalf("parse forward endpoint: %v", err)
	}

	cfg := config.Config{
		SubscribeURL:    "https://sub.example.com/api",
		SubscribeFilter: "日本",
		DialTimeout:     50 * time.Millisecond,
		ForwardChain:    []endpoint.Endpoint{forward},
	}

	rtProvider, err := buildRouter(cfg)
	if err != nil {
		t.Fatalf("buildRouter error: %v", err)
	}

	rt, err := rtProvider.Route(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("route resolve error: %v", err)
	}

	balancer, ok := rt.(*chain.BalancerRoute)
	if !ok {
		t.Fatalf("route type = %T, want *chain.BalancerRoute", rt)
	}
	defer balancer.Close()

	nodes := rt.Nodes()
	if len(nodes) != 1 {
		t.Fatalf("nodes length = %d, want 1", len(nodes))
	}
	if got := nodes[0].Display; got != "日本-VMess" {
		t.Fatalf("first node display = %q, want %q", got, "日本-VMess")
	}
}

func stubSubscribeDownload(t *testing.T, body string) {
	t.Helper()

	old := subscribeDownload
	subscribeDownload = func(string) ([]byte, error) {
		return []byte(body), nil
	}
	t.Cleanup(func() {
		subscribeDownload = old
	})
}
