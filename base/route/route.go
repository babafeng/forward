package route

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"forward/base/logging"
	"forward/base/mmdb"
)

type Decision struct {
	Via   string
	Chain []string
}

type Router struct {
	rules     []compiledRule
	skipProxy []netip.Prefix
	resolver  *resolver
	mmdb      *mmdb.Reader
	hasIPRule bool
}

type compiledRule struct {
	typ     RuleType
	action  Action
	domain  string
	suffix  string
	keyword string
	cidr    netip.Prefix
	country string
}

func NewRouter(cfg *Config, log *logging.Logger) (*Router, error) {
	if cfg == nil {
		return nil, nil
	}

	dnsTimeout := cfg.DNSTimeout
	if dnsTimeout <= 0 {
		dnsTimeout = 5 * time.Second
	}

	r := &Router{
		skipProxy: append([]netip.Prefix(nil), cfg.SkipProxy...),
		resolver:  newResolver(cfg.DNSServers, dnsTimeout),
	}

	var hasGeoIP bool
	for _, rule := range cfg.Rules {
		if rule.Action.Type == ActionProxy {
			if cfg.Proxies == nil {
				return nil, fmt.Errorf("route rule references proxy %s but no proxies configured", rule.Action.Proxy)
			}
			for _, name := range rule.Action.ProxyNames() {
				if _, ok := cfg.Proxies[name]; !ok {
					return nil, fmt.Errorf("route rule references unknown proxy %s", name)
				}
			}
		}
		cr, err := compileRule(rule)
		if err != nil {
			return nil, err
		}
		if cr.typ == RuleIPCIDR {
			r.hasIPRule = true
		}
		if cr.typ == RuleGEOIP {
			hasGeoIP = true
			r.hasIPRule = true
		}
		r.rules = append(r.rules, cr)
	}

	if len(r.skipProxy) > 0 {
		r.hasIPRule = true
	}

	if hasGeoIP {
		mmdbPath, err := ensureMMDB(cfg.MMDBPath, cfg.MMDBLink, log)
		if err != nil {
			return nil, err
		}
		reader, err := mmdb.Open(mmdbPath)
		if err != nil {
			return nil, err
		}
		r.mmdb = reader
	}

	return r, nil
}

func (r *Router) Decide(ctx context.Context, address string) (Decision, error) {
	if r == nil {
		return Decision{Via: "DIRECT"}, nil
	}
	host := normalizeHost(address)
	if host == "" {
		return Decision{Via: "DIRECT"}, nil
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else if r.hasIPRule {
		resolved, err := r.resolver.lookupIPs(ctx, host)
		if err != nil {
			return Decision{Via: "DIRECT"}, err
		}
		ips = resolved
	}

	if len(ips) > 0 && len(r.skipProxy) > 0 {
		for _, ip := range ips {
			if matchPrefixes(ip, r.skipProxy) {
				return Decision{Via: "DIRECT"}, nil
			}
		}
	}

	for _, rule := range r.rules {
		if ruleMatch(rule, host, ips, r.mmdb) {
			return actionDecision(rule.action), nil
		}
	}

	return Decision{Via: "DIRECT"}, nil
}

func (r *Router) Close() error {
	if r == nil || r.mmdb == nil {
		return nil
	}
	return r.mmdb.Close()
}

func compileRule(rule Rule) (compiledRule, error) {
	val := strings.TrimSpace(rule.Value)
	switch rule.Type {
	case RuleDomain:
		return compiledRule{typ: rule.Type, action: rule.Action, domain: normalizeHost(val)}, nil
	case RuleDomainSuffix:
		return compiledRule{typ: rule.Type, action: rule.Action, suffix: normalizeHost(strings.TrimPrefix(val, "."))}, nil
	case RuleDomainKeyword:
		return compiledRule{typ: rule.Type, action: rule.Action, keyword: strings.ToLower(val)}, nil
	case RuleIPCIDR:
		prefix, err := netip.ParsePrefix(val)
		if err != nil {
			return compiledRule{}, fmt.Errorf("invalid IP-CIDR %q: %w", val, err)
		}
		return compiledRule{typ: rule.Type, action: rule.Action, cidr: prefix}, nil
	case RuleGEOIP:
		if val == "" {
			return compiledRule{}, fmt.Errorf("GEOIP requires country code")
		}
		return compiledRule{typ: rule.Type, action: rule.Action, country: strings.ToUpper(val)}, nil
	case RuleFinal:
		return compiledRule{typ: rule.Type, action: rule.Action}, nil
	default:
		return compiledRule{}, fmt.Errorf("unsupported rule type %q", rule.Type)
	}
}

func ruleMatch(rule compiledRule, host string, ips []net.IP, db *mmdb.Reader) bool {
	switch rule.typ {
	case RuleDomain:
		return host == rule.domain
	case RuleDomainSuffix:
		return host == rule.suffix || strings.HasSuffix(host, "."+rule.suffix)
	case RuleDomainKeyword:
		return strings.Contains(host, rule.keyword)
	case RuleIPCIDR:
		for _, ip := range ips {
			if matchPrefix(ip, rule.cidr) {
				return true
			}
		}
		return false
	case RuleGEOIP:
		if db == nil {
			return false
		}
		for _, ip := range ips {
			cc, err := db.CountryCode(ip)
			if err != nil {
				continue
			}
			if strings.EqualFold(cc, rule.country) {
				return true
			}
		}
		return false
	case RuleFinal:
		return true
	default:
		return false
	}
}

func actionDecision(a Action) Decision {
	switch a.Type {
	case ActionReject:
		return Decision{Via: "REJECT"}
	case ActionProxy:
		chain := a.ProxyNames()
		if len(chain) == 0 {
			return Decision{Via: "DIRECT"}
		}
		return Decision{
			Via:   strings.Join(chain, " -> "),
			Chain: chain,
		}
	default:
		return Decision{Via: "DIRECT"}
	}
}

func normalizeHost(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func matchPrefix(ip net.IP, prefix netip.Prefix) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	return prefix.Contains(addr)
}

func matchPrefixes(ip net.IP, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if matchPrefix(ip, p) {
			return true
		}
	}
	return false
}

type resolver struct {
	servers []string
	timeout time.Duration
}

func newResolver(servers []string, timeout time.Duration) *resolver {
	clean := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		clean = append(clean, s)
	}
	return &resolver{
		servers: clean,
		timeout: timeout,
	}
}

func (r *resolver) lookupIPs(ctx context.Context, host string) ([]net.IP, error) {
	if host == "" {
		return nil, nil
	}

	// 强制使用 DNS 超时，避免依赖调用方 ctx
	timeout := r.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if len(r.servers) == 0 {
		return net.DefaultResolver.LookupIP(ctx, "ip", host)
	}
	for _, s := range r.servers {
		serverAddr := normalizeDNSServer(s)
		res := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: r.timeout}
				return d.DialContext(ctx, network, serverAddr)
			},
		}
		ips, err := res.LookupIP(ctx, "ip", host)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func normalizeDNSServer(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	if ip := net.ParseIP(server); ip != nil {
		if ip.To4() != nil {
			return net.JoinHostPort(server, "53")
		}
		return net.JoinHostPort("["+server+"]", "53")
	}
	return net.JoinHostPort(server, "53")
}

func ensureMMDB(path, link string, log *logging.Logger) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("mmdb path is required for GEOIP rules")
	}
	path = os.ExpandEnv(path)
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand mmdb path: %w", err)
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~"))
	}
	path = filepath.Clean(path)

	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	if strings.TrimSpace(link) == "" {
		return "", fmt.Errorf("mmdb file not found at %s and mmdb link is empty", path)
	}

	if !strings.HasPrefix(strings.ToLower(link), "https://") {
		return "", fmt.Errorf("mmdb link must use HTTPS for security: %s", link)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create mmdb dir: %w", err)
	}

	if log != nil {
		log.Info("Download mmdb from %s", link)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("insecure redirect to %s", req.URL)
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", link, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download mmdb: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download mmdb: status %s", resp.Status)
	}

	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return "", fmt.Errorf("create mmdb file: %w", err)
	}

	// Limit 50MB
	limitReader := io.LimitReader(resp.Body, 50*1024*1024)
	if _, err := io.Copy(f, limitReader); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("write mmdb file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("close mmdb file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("rename mmdb file: %w", err)
	}
	return path, nil
}
