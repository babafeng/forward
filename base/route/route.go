package route

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"forward/base/logging"
	"forward/base/mmdb"
	"forward/internal/netmark"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

type Decision struct {
	Via     string
	Chain   []string
	Matched bool
	// UseSubscribe means the matched proxy action should be prefixed with the
	// subscription balancer when available.
	UseSubscribe bool
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
		if err == nil {
			ips = resolved
		}
	}

	if len(ips) > 0 && len(r.skipProxy) > 0 {
		for _, ip := range ips {
			if matchPrefixes(ip, r.skipProxy) {
				return directDecision(true), nil
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
		return Decision{Via: "REJECT", Matched: true}
	case ActionProxy:
		chain := a.ProxyNames()
		if len(chain) == 0 {
			return directDecision(true)
		}
		via := strings.Join(chain, " -> ")
		if a.UseSubscribe {
			via = "SUBSCRIBE -> " + via
		}
		return Decision{
			Via:          via,
			Chain:        chain,
			Matched:      true,
			UseSubscribe: a.UseSubscribe,
		}
	default:
		return directDecision(true)
	}
}

func directDecision(matched bool) Decision {
	return Decision{Via: "DIRECT", Matched: matched}
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
	servers  []dnsServer
	timeout  time.Duration
	cacheTTL time.Duration

	cache sync.Map
	sf    singleflight.Group
}

type dnsServerKind int

const (
	dnsServerPlain dnsServerKind = iota
	dnsServerDoH
	dnsServerDoT
)

type dnsServer struct {
	raw        string
	kind       dnsServerKind
	network    string
	address    string
	url        string
	serverName string
	dohClient  *http.Client
	dotClient  *dns.Client
}

type dnsCacheEntry struct {
	ips      []net.IP
	expireAt int64
}

const defaultDNSCacheTTL = 30 * time.Second

func newResolver(servers []string, timeout time.Duration) *resolver {
	clean := make([]dnsServer, 0, len(servers))
	for _, s := range servers {
		server, ok := parseDNSServer(s)
		if !ok {
			continue
		}
		server = prepareDNSServer(server, timeout)
		clean = append(clean, server)
	}
	return &resolver{
		servers:  clean,
		timeout:  timeout,
		cacheTTL: defaultDNSCacheTTL,
	}
}

func (r *resolver) lookupIPs(ctx context.Context, host string) ([]net.IP, error) {
	if host == "" {
		return nil, nil
	}

	if ips, ok := r.loadCache(host); ok {
		return ips, nil
	}

	result, err, _ := r.sf.Do(host, func() (any, error) {
		if ips, ok := r.loadCache(host); ok {
			return ips, nil
		}
		ips, err := r.lookupUncached(ctx, host)
		if err != nil {
			return nil, err
		}
		r.storeCache(host, ips)
		return cloneIPs(ips), nil
	})
	if err != nil {
		return nil, err
	}
	ips, _ := result.([]net.IP)
	return cloneIPs(ips), nil
}

func (r *resolver) lookupUncached(ctx context.Context, host string) ([]net.IP, error) {
	// 强制使用 DNS 超时，避免依赖调用方 ctx
	timeout := r.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if len(r.servers) == 0 {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		return cloneIPs(ips), nil
	}
	for _, s := range r.servers {
		ips, err := r.lookupWithServer(ctx, host, s)
		if err == nil && len(ips) > 0 {
			return cloneIPs(ips), nil
		}
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return cloneIPs(ips), nil
}

func (r *resolver) lookupWithServer(ctx context.Context, host string, server dnsServer) ([]net.IP, error) {
	switch server.kind {
	case dnsServerDoH:
		return r.lookupDoH(ctx, host, server)
	case dnsServerDoT:
		return r.lookupDoT(ctx, host, server)
	default:
		return r.lookupPlainDNS(ctx, host, server)
	}
}

func (r *resolver) lookupPlainDNS(ctx context.Context, host string, server dnsServer) ([]net.IP, error) {
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if server.network != "" {
				network = server.network
			}
			d := net.Dialer{Timeout: r.timeout}
			netmark.ConfigureDialer(&d)
			return d.DialContext(ctx, network, server.address)
		},
	}
	ips, err := res.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return cloneIPs(ips), nil
}

func (r *resolver) lookupDoT(ctx context.Context, host string, server dnsServer) ([]net.IP, error) {
	client := server.dotClient
	if client == nil {
		client = newDoTClient(r.timeout, server.serverName)
	}
	return lookupDNSMessages(ctx, host, func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
		resp, _, err := client.ExchangeContext(ctx, msg, server.address)
		return resp, err
	})
}

func (r *resolver) lookupDoH(ctx context.Context, host string, server dnsServer) ([]net.IP, error) {
	client := server.dohClient
	if client == nil {
		client = newDoHClient(r.timeout)
	}
	return lookupDNSMessages(ctx, host, func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
		wire, err := msg.Pack()
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.url, bytes.NewReader(wire))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/dns-message")
		req.Header.Set("Content-Type", "application/dns-message")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("doh status %s", resp.Status)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		answer := new(dns.Msg)
		if err := answer.Unpack(body); err != nil {
			return nil, err
		}
		return answer, nil
	})
}

func prepareDNSServer(server dnsServer, timeout time.Duration) dnsServer {
	switch server.kind {
	case dnsServerDoH:
		server.dohClient = newDoHClient(timeout)
	case dnsServerDoT:
		server.dotClient = newDoTClient(timeout, server.serverName)
	}
	return server
}

func newDoTClient(timeout time.Duration, serverName string) *dns.Client {
	return &dns.Client{
		Net:     "tcp-tls",
		Timeout: timeout,
		Dialer:  configuredNetDialer(timeout),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: serverName,
		},
	}
}

func newDoHClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				netmark.ConfigureDialer(&d)
				return d.DialContext(ctx, network, address)
			},
			TLSHandshakeTimeout: timeout,
		},
	}
}

func lookupDNSMessages(ctx context.Context, host string, exchange func(context.Context, *dns.Msg) (*dns.Msg, error)) ([]net.IP, error) {
	var out []net.IP
	var lastErr error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), qtype)
		msg.RecursionDesired = true
		resp, err := exchange(ctx, msg)
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil {
			lastErr = fmt.Errorf("empty dns response")
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("dns rcode %s", dns.RcodeToString[resp.Rcode])
			continue
		}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				out = append(out, v.A)
			case *dns.AAAA:
				out = append(out, v.AAAA)
			}
		}
	}
	if len(out) > 0 {
		return cloneIPs(out), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no dns answers for %s", host)
	}
	return nil, lastErr
}

func configuredNetDialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	netmark.ConfigureDialer(d)
	return d
}

func parseDNSServer(raw string) (dnsServer, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return dnsServer{}, false
	}
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "https://"):
		if _, err := url.ParseRequestURI(raw); err != nil {
			return dnsServer{}, false
		}
		return dnsServer{raw: raw, kind: dnsServerDoH, url: raw}, true
	case strings.HasPrefix(lower, "tls://"), strings.HasPrefix(lower, "dot://"):
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return dnsServer{}, false
		}
		return dnsServer{
			raw:        raw,
			kind:       dnsServerDoT,
			address:    normalizeDNSServerPort(u.Host, "853"),
			serverName: dnsTLSServerName(u.Host),
		}, true
	case strings.HasPrefix(lower, "udp://"), strings.HasPrefix(lower, "tcp://"):
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return dnsServer{}, false
		}
		return dnsServer{
			raw:     raw,
			kind:    dnsServerPlain,
			network: strings.ToLower(u.Scheme),
			address: normalizeDNSServer(u.Host),
		}, true
	default:
		return dnsServer{raw: raw, kind: dnsServerPlain, address: normalizeDNSServer(raw)}, true
	}
}

func dnsTLSServerName(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host
}

func (r *resolver) loadCache(host string) ([]net.IP, bool) {
	if r == nil || r.cacheTTL <= 0 {
		return nil, false
	}
	v, ok := r.cache.Load(host)
	if !ok {
		return nil, false
	}
	entry, ok := v.(dnsCacheEntry)
	if !ok {
		r.cache.Delete(host)
		return nil, false
	}
	if time.Now().UnixNano() >= entry.expireAt {
		r.cache.Delete(host)
		return nil, false
	}
	return cloneIPs(entry.ips), true
}

func (r *resolver) storeCache(host string, ips []net.IP) {
	if r == nil || r.cacheTTL <= 0 || len(ips) == 0 {
		return
	}
	r.cache.Store(host, dnsCacheEntry{
		ips:      cloneIPs(ips),
		expireAt: time.Now().Add(r.cacheTTL).UnixNano(),
	})
}

func cloneIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		cp := make(net.IP, len(ip))
		copy(cp, ip)
		out = append(out, cp)
	}
	return out
}

func normalizeDNSServer(server string) string {
	return normalizeDNSServerPort(server, "53")
}

func normalizeDNSServerPort(server, defaultPort string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	host := strings.TrimPrefix(strings.TrimSuffix(server, "]"), "[")
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(host, defaultPort)
	}
	return net.JoinHostPort(server, defaultPort)
}

func ensureMMDB(path, link string, log *logging.Logger) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("mmdb path is required for GEOIP rules")
	}
	path = os.ExpandEnv(path)
	if strings.HasPrefix(path, "~") {
		home, err := currentHomeDir()
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

func currentHomeDir() (string, error) {
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return home, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(u.HomeDir) == "" {
		return "", fmt.Errorf("home directory is empty for user %s", u.Username)
	}
	return u.HomeDir, nil
}
