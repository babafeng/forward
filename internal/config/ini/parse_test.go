package ini

import (
	"testing"

	"forward/base/route"
)

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
}

func TestParseRuleLineDirectCannotChain(t *testing.T) {
	_, err := parseRuleLine("DOMAIN,ipconfig.me,DIRECT,PROXY_1")
	if err == nil {
		t.Fatal("expected parseRuleLine error for chained DIRECT action")
	}
}
