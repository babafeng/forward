package ini

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"forward/internal/config"
	"forward/inner/endpoint"
	"forward/inner/logging"
	"forward/inner/route"
)

func ParseFile(path string) (config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config.Config{}, fmt.Errorf("read config file: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (config.Config, error) {
	var (
		section   string
		lineNo    int
		general   = map[string]string{}
		proxies   = map[string]string{}
		ruleLines []string
	)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		switch section {
		case "general", "proxy":
			key, val, ok := strings.Cut(line, "=")
			if !ok {
				return config.Config{}, fmt.Errorf("line %d: invalid key=value", lineNo)
			}
			key = strings.ToLower(strings.TrimSpace(key))
			val = strings.TrimSpace(val)
			if section == "general" {
				general[key] = val
			} else {
				if key != "" {
					proxies[key] = val
				}
			}
		case "rule":
			ruleLines = append(ruleLines, line)
		default:
			return config.Config{}, fmt.Errorf("line %d: unknown section %q", lineNo, section)
		}
	}
	if err := scanner.Err(); err != nil {
		return config.Config{}, err
	}

	listenRaw := strings.TrimSpace(general["listen"])
	if listenRaw == "" {
		return config.Config{}, fmt.Errorf("general.listen is required")
	}
	listeners, err := parseEndpointList(listenRaw)
	if err != nil {
		return config.Config{}, err
	}

	logLevel := "info"
	if strings.EqualFold(strings.TrimSpace(general["debug"]), "true") {
		logLevel = "debug"
	}
	llevel, err := logging.ParseLevel(logLevel)
	if err != nil {
		return config.Config{}, err
	}

	cfg := config.Config{
		Listeners: listeners,
		Listen:    listeners[0],
		Logger:    logging.New(logging.Options{Level: llevel}),
		LogLevel:  llevel,
	}

	rcfg := &route.Config{
		Proxies:    map[string]endpoint.Endpoint{},
		SkipProxy:  parsePrefixList(general["skip-proxy"]),
		DNSServers: parseCommaList(general["dns-server"]),
		MMDBPath:   strings.TrimSpace(general["mmdb-path"]),
		MMDBLink:   strings.TrimSpace(general["mmdb-link"]),
	}
	for name, raw := range proxies {
		normalized := route.NormalizeProxyName(name)
		if raw == "" {
			return config.Config{}, fmt.Errorf("proxy %s is empty", name)
		}
		ep, err := endpoint.Parse(raw)
		if err != nil {
			return config.Config{}, fmt.Errorf("proxy %s parse error: %w", name, err)
		}
		rcfg.Proxies[normalized] = ep
	}

	for _, raw := range ruleLines {
		rule, err := parseRuleLine(raw)
		if err != nil {
			return config.Config{}, err
		}
		rcfg.Rules = append(rcfg.Rules, rule)
	}

	cfg.Route = rcfg
	cfg.Nodes = []config.NodeConfig{{
		Name:      "default",
		Listeners: listeners,
	}}

	config.ApplyDefaults(&cfg)
	return cfg, nil
}

func parseEndpointList(raw string) ([]endpoint.Endpoint, error) {
	parts := parseCommaList(raw)
	if len(parts) == 0 {
		return nil, fmt.Errorf("listen is empty")
	}
	list := make([]endpoint.Endpoint, 0, len(parts))
	for _, p := range parts {
		ep, err := endpoint.Parse(p)
		if err != nil {
			return nil, fmt.Errorf("parse listen %s: %w", p, err)
		}
		list = append(list, ep)
	}
	return list, nil
}

func parseRuleLine(line string) (route.Rule, error) {
	parts := strings.Split(line, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) < 2 {
		return route.Rule{}, fmt.Errorf("invalid rule: %s", line)
	}

	ruleType := route.RuleType(strings.ToUpper(parts[0]))
	value := ""
	action := ""

	if ruleType == route.RuleFinal {
		action = parts[1]
	} else {
		if len(parts) < 3 {
			return route.Rule{}, fmt.Errorf("invalid rule: %s", line)
		}
		value = parts[1]
		action = parts[2]
	}

	act, err := parseAction(action)
	if err != nil {
		return route.Rule{}, err
	}

	return route.Rule{
		Type:   ruleType,
		Value:  value,
		Action: act,
	}, nil
}

func parseAction(raw string) (route.Action, error) {
	action := strings.ToUpper(strings.TrimSpace(raw))
	switch action {
	case "DIRECT":
		return route.Action{Type: route.ActionDirect}, nil
	case "REJECT":
		return route.Action{Type: route.ActionReject}, nil
	case "":
		return route.Action{}, fmt.Errorf("rule action is empty")
	default:
		return route.Action{Type: route.ActionProxy, Proxy: route.NormalizeProxyName(action)}, nil
	}
}

func parseCommaList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePrefixList(raw string) []netip.Prefix {
	parts := parseCommaList(raw)
	out := make([]netip.Prefix, 0, len(parts))
	for _, p := range parts {
		if prefix, err := netip.ParsePrefix(p); err == nil {
			out = append(out, prefix)
			continue
		}
		if addr, err := netip.ParseAddr(p); err == nil {
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			out = append(out, netip.PrefixFrom(addr, bits))
		}
	}
	return out
}
