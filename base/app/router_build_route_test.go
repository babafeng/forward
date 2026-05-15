package app

import (
	"context"
	"testing"
	"time"

	"forward/base/endpoint"
	"forward/base/route"
	"forward/internal/chain"
	"forward/internal/config"
)

func TestBuildRouterNamedProxyUsesProxyNameInSummary(t *testing.T) {
	ep, err := endpoint.Parse("socks5://1.2.3.4:443")
	if err != nil {
		t.Fatalf("parse proxy endpoint: %v", err)
	}

	cfg := config.Config{
		DialTimeout: 50 * time.Millisecond,
		Route: &route.Config{
			Proxies: map[string]endpoint.Endpoint{
				"PROXY_HK_01": ep,
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
		},
	}

	rtProvider, err := buildRouter(cfg)
	if err != nil {
		t.Fatalf("buildRouter error: %v", err)
	}

	rt, err := rtProvider.Route(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("route resolve error: %v", err)
	}

	if got := chain.RouteSummary(rt); got != "PROXY_HK_01(1.2.3.4:443)" {
		t.Fatalf("RouteSummary = %q, want %q", got, "PROXY_HK_01(1.2.3.4:443)")
	}
}
