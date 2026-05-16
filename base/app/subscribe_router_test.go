package app

import (
	"context"
	"fmt"
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

func TestBuildRouterSubscribeStripsFlagFromNodeDisplay(t *testing.T) {
	stubSubscribeDownload(t, `
proxies:
  - name: "🇺🇲 美国 | V1 | 03"
    type: vmess
    server: 127.0.0.1
    port: 10086
    uuid: "11111111-1111-1111-1111-111111111111"
    alterId: 0
    cipher: auto
`)

	cfg := config.Config{
		SubscribeURL:    "https://sub.example.com/api",
		SubscribeFilter: "美国",
		DialTimeout:     50 * time.Millisecond,
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
	if got := nodes[0].Display; got != "美国 | V1 | 03" {
		t.Fatalf("first node display = %q, want %q", got, "美国 | V1 | 03")
	}
}

func TestBuildRouterSubscribeWithMultipleSourcesMergesAndDeduplicates(t *testing.T) {
	stubSubscribeDownloadMap(t, map[string]string{
		"https://sub1.example.com/api": `
proxies:
  - name: "日本-VMess"
    type: vmess
    server: 127.0.0.1
    port: 10086
    uuid: "11111111-1111-1111-1111-111111111111"
    alterId: 0
    cipher: auto
  - name: "共享-VMess"
    type: vmess
    server: 127.0.0.1
    port: 10088
    uuid: "33333333-3333-3333-3333-333333333333"
    alterId: 0
    cipher: auto
`,
		"https://sub2.example.com/api": `
proxies:
  - name: "US-VMess"
    type: vmess
    server: 127.0.0.1
    port: 10087
    uuid: "22222222-2222-2222-2222-222222222222"
    alterId: 0
    cipher: auto
  - name: "共享-重复名称"
    type: vmess
    server: 127.0.0.1
    port: 10088
    uuid: "33333333-3333-3333-3333-333333333333"
    alterId: 0
    cipher: auto
`,
	})

	cfg := config.Config{
		SubscribeURL:  "https://sub1.example.com/api",
		SubscribeURLs: []string{"https://sub1.example.com/api", "https://sub2.example.com/api"},
		DialTimeout:   50 * time.Millisecond,
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
	if len(nodes) != 3 {
		t.Fatalf("nodes length = %d, want 3", len(nodes))
	}
}

func TestBuildRouterSubscribeWithMultipleSourcesAllowsPartialFailure(t *testing.T) {
	stubSubscribeDownloadMap(t, map[string]string{
		"https://sub1.example.com/api": `
proxies:
  - name: "日本-VMess"
    type: vmess
    server: 127.0.0.1
    port: 10086
    uuid: "11111111-1111-1111-1111-111111111111"
    alterId: 0
    cipher: auto
`,
	})

	cfg := config.Config{
		SubscribeURLs: []string{
			"https://sub1.example.com/api",
			"https://sub2.example.com/api",
		},
		DialTimeout: 50 * time.Millisecond,
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

func TestSplitSubscribeValues(t *testing.T) {
	got := splitSubscribeValues([]string{
		"https://sub1.example.com/api, https://sub2.example.com/api",
		"https://sub2.example.com/api",
		" https://sub3.example.com/api ",
	})

	want := []string{
		"https://sub1.example.com/api",
		"https://sub2.example.com/api",
		"https://sub3.example.com/api",
	}
	if len(got) != len(want) {
		t.Fatalf("splitSubscribeValues length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitSubscribeValues[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBuildNodeConfigCopiesNodeSubscribeSettings(t *testing.T) {
	global := config.Config{
		SubscribeURL:    "https://global.example.com/sub",
		SubscribeURLs:   []string{"https://global.example.com/sub"},
		SubscribeFilter: "US",
		SubscribeUpdate: 60,
	}
	node := config.NodeConfig{
		Name:            "node-a",
		Listeners:       []endpoint.Endpoint{{Scheme: "http"}},
		SubscribeURL:    "https://legacy.example.com/sub",
		SubscribeURLs:   []string{"https://legacy.example.com/sub", "https://sub2.example.com/sub"},
		SubscribeFilter: "日本",
		SubscribeUpdate: 15,
	}

	cfg := buildNodeConfig(global, node, endpoint.Endpoint{Scheme: "http"})

	wantURLs := []string{
		"https://legacy.example.com/sub",
		"https://sub2.example.com/sub",
	}
	gotURLs := cfg.EffectiveSubscribeURLs()
	if len(gotURLs) != len(wantURLs) {
		t.Fatalf("effective subscribe urls length = %d, want %d", len(gotURLs), len(wantURLs))
	}
	for i := range wantURLs {
		if gotURLs[i] != wantURLs[i] {
			t.Fatalf("effective subscribe urls[%d] = %q, want %q", i, gotURLs[i], wantURLs[i])
		}
	}
	if cfg.SubscribeFilter != "日本" {
		t.Fatalf("SubscribeFilter = %q, want %q", cfg.SubscribeFilter, "日本")
	}
	if cfg.SubscribeUpdate != 15 {
		t.Fatalf("SubscribeUpdate = %d, want %d", cfg.SubscribeUpdate, 15)
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

func stubSubscribeDownloadMap(t *testing.T, bodies map[string]string) {
	t.Helper()

	old := subscribeDownload
	subscribeDownload = func(rawURL string) ([]byte, error) {
		body, ok := bodies[rawURL]
		if !ok {
			return nil, fmt.Errorf("unexpected subscribe url %s", rawURL)
		}
		return []byte(body), nil
	}
	t.Cleanup(func() {
		subscribeDownload = old
	})
}
