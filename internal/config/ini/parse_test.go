package ini

import (
	"reflect"
	"testing"

	"forward/base/route"
)

func TestParseSupportsMultipleSubscribeSources(t *testing.T) {
	cfg, err := Parse([]byte(`
[general]
listen = http://127.0.0.1:1080
subscribe = https://legacy.example.com/sub
subscribes = https://sub1.example.com/sub, https://sub2.example.com/sub
filter = 日本
update = 30
`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	want := []string{
		"https://legacy.example.com/sub",
		"https://sub1.example.com/sub",
		"https://sub2.example.com/sub",
	}
	got := cfg.EffectiveSubscribeURLs()
	if len(got) != len(want) {
		t.Fatalf("effective subscribe urls length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("effective subscribe urls[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if cfg.SubscribeFilter != "日本" {
		t.Fatalf("SubscribeFilter = %q, want %q", cfg.SubscribeFilter, "日本")
	}
	if cfg.SubscribeUpdate != 30 {
		t.Fatalf("SubscribeUpdate = %d, want %d", cfg.SubscribeUpdate, 30)
	}
}

func TestParseRuleLineProxyChain(t *testing.T) {
	rule, err := parseRuleLine("DOMAIN,ipconfig.me,PROXY_2,PROXY_1")
	if err != nil {
		t.Fatalf("parseRuleLine returned error: %v", err)
	}

	if rule.Type != route.RuleDomain {
		t.Fatalf("rule.Type = %s, want %s", rule.Type, route.RuleDomain)
	}
	if rule.Action.Type != route.ActionProxy {
		t.Fatalf("rule.Action.Type = %d, want %d", rule.Action.Type, route.ActionProxy)
	}

	wantChain := []string{"PROXY_1", "PROXY_2"}
	got := rule.Action.ProxyNames()
	if len(got) != len(wantChain) {
		t.Fatalf("proxy chain length = %d, want %d", len(got), len(wantChain))
	}
	for i := range got {
		if got[i] != wantChain[i] {
			t.Fatalf("proxy chain[%d] = %s, want %s", i, got[i], wantChain[i])
		}
	}
	if rule.Action.UseSubscribe {
		t.Fatal("rule.Action.UseSubscribe = true, want false")
	}
}

func TestParseRuleLineProxyChainWithSubscribeMarker(t *testing.T) {
	rule, err := parseRuleLine("DOMAIN,ipconfig.me,SUBSCRIBE,PROXY_2,PROXY_1")
	if err != nil {
		t.Fatalf("parseRuleLine returned error: %v", err)
	}

	if !rule.Action.UseSubscribe {
		t.Fatal("rule.Action.UseSubscribe = false, want true")
	}

	wantChain := []string{"PROXY_1", "PROXY_2"}
	got := rule.Action.ProxyNames()
	if len(got) != len(wantChain) {
		t.Fatalf("proxy chain length = %d, want %d", len(got), len(wantChain))
	}
	for i := range got {
		if got[i] != wantChain[i] {
			t.Fatalf("proxy chain[%d] = %s, want %s", i, got[i], wantChain[i])
		}
	}
}

func TestParseRuleLineDirectCannotChain(t *testing.T) {
	_, err := parseRuleLine("DOMAIN,ipconfig.me,DIRECT,PROXY_1")
	if err == nil {
		t.Fatal("expected parseRuleLine error for chained DIRECT action")
	}
}

func TestParseRuleLineDirectCannotUseSubscribeMarker(t *testing.T) {
	_, err := parseRuleLine("DOMAIN,ipconfig.me,SUBSCRIBE,DIRECT")
	if err == nil {
		t.Fatal("expected parseRuleLine error for SUBSCRIBE + DIRECT action")
	}
}

func TestParseSubscribeCommaSeparated(t *testing.T) {
	cfg, err := Parse([]byte(`
[general]
listen = http://:1080
subscribe = https://sub-a.example.com/api, https://sub-b.example.com/api
`))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if cfg.SubscribeURL != "https://sub-a.example.com/api" {
		t.Fatalf("cfg.SubscribeURL = %q, want %q", cfg.SubscribeURL, "https://sub-a.example.com/api")
	}
	if len(cfg.SubscribeURLs) != 2 {
		t.Fatalf("cfg.SubscribeURLs length = %d, want 2", len(cfg.SubscribeURLs))
	}
	if cfg.SubscribeURLs[1] != "https://sub-b.example.com/api" {
		t.Fatalf("cfg.SubscribeURLs[1] = %q, want %q", cfg.SubscribeURLs[1], "https://sub-b.example.com/api")
	}
}

func TestParseTProxyNetworkExplicitModes(t *testing.T) {
	tests := []struct {
		name    string
		network string
		want    []string
	}{
		{name: "tcp_only", network: "tcp", want: []string{"tcp"}},
		{name: "udp_only", network: "udp", want: []string{"udp"}},
		{name: "tcp_udp", network: "tcp,udp", want: []string{"tcp", "udp"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse([]byte(`
[General]
listen = http://127.0.0.1:1080
tproxy = 12345

[TProxy]
network = ` + tt.network + `
`))
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}
			if cfg.TProxy == nil {
				t.Fatal("cfg.TProxy should not be nil")
			}
			if !reflect.DeepEqual(cfg.TProxy.Network, tt.want) {
				t.Fatalf("cfg.TProxy.Network = %v, want %v", cfg.TProxy.Network, tt.want)
			}
		})
	}
}
