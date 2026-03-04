package route

import (
	"net/netip"
	"strings"
	"time"

	"forward/base/endpoint"
)

type ActionType int

const (
	ActionDirect ActionType = iota
	ActionReject
	ActionProxy
)

type Action struct {
	Type       ActionType
	Proxy      string
	ProxyChain []string
}

type RuleType string

const (
	RuleDomain        RuleType = "DOMAIN"
	RuleDomainSuffix  RuleType = "DOMAIN-SUFFIX"
	RuleDomainKeyword RuleType = "DOMAIN-KEYWORD"
	RuleIPCIDR        RuleType = "IP-CIDR"
	RuleGEOIP         RuleType = "GEOIP"
	RuleFinal         RuleType = "FINAL"
)

type Rule struct {
	Type   RuleType
	Value  string
	Action Action
}

type Config struct {
	Proxies    map[string]endpoint.Endpoint
	Rules      []Rule
	SkipProxy  []netip.Prefix
	DNSServers []string
	DNSTimeout time.Duration
	MMDBPath   string
	MMDBLink   string
}

func NormalizeProxyName(name string) string {
	return strings.ToUpper(strings.TrimSpace(name))
}

func (a Action) ProxyNames() []string {
	if len(a.ProxyChain) > 0 {
		out := make([]string, 0, len(a.ProxyChain))
		for _, name := range a.ProxyChain {
			normalized := NormalizeProxyName(name)
			if normalized != "" {
				out = append(out, normalized)
			}
		}
		return out
	}
	if a.Proxy == "" {
		return nil
	}
	return []string{NormalizeProxyName(a.Proxy)}
}
