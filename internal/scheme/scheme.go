package scheme

import (
	"fmt"
	"strings"
)

type TransportKind string

const (
	TransportNone TransportKind = ""
	TransportTLS  TransportKind = "tls"
	TransportDTLS TransportKind = "dtls"
	TransportH2   TransportKind = "h2"
	TransportH3   TransportKind = "h3"
	TransportQUIC TransportKind = "quic"
)

type RouteTypes struct {
	Connector string
	Dialer    string
}

type ProxyTypes struct {
	Handler   string
	Listener  string
	Transport TransportKind
}

var directTransports = map[string]struct {
	base      string
	transport TransportKind
}{
	"https":         {"http", TransportTLS},
	"http2":         {"http2", TransportNone},
	"http3":         {"http3", TransportNone},
	"quic":          {"tcp", TransportQUIC},
	"tls":           {"http", TransportTLS},
	"h2":            {"http", TransportH2},
	"h3":            {"http", TransportH3},
	"dtls":          {"tcp", TransportDTLS},
	"hysteria2":     {"hysteria2", TransportNone},
	"hy2":           {"hysteria2", TransportNone},
	"vless":         {"vless", TransportNone},
	"vless+reality": {"vless", TransportNone},
	"reality":       {"vless", TransportNone},
	"vless+tls":     {"vless", TransportTLS},
	"vmess":         {"vmess", TransportNone},
	"vmess+tls":     {"vmess", TransportTLS},
	"trojan":        {"trojan", TransportTLS},
	"trojan+tls":    {"trojan", TransportTLS},
}

var transportSuffixes = []struct {
	suffix    string
	transport TransportKind
}{
	{"+tls", TransportTLS},
	{"+h2", TransportH2},
	{"+h3", TransportH3},
	{"+dtls", TransportDTLS},
	{"+quic", TransportQUIC},
	{"+reality", TransportNone},
}

var routeTypes = map[string]RouteTypes{
	"http":            {"http", "tcp"},
	"https":           {"http", "tls"},
	"http+tls":        {"http", "tls"},
	"tls":             {"http", "tls"},
	"http2":           {"http2", "tls"},
	"http3":           {"http3", "http3"},
	"h2":              {"http", "h2"},
	"h3":              {"http", "h3"},
	"socks5":          {"socks5", "tcp"},
	"socks5h":         {"socks5", "tcp"},
	"tcp":             {"tcp", "tcp"},
	"quic":            {"tcp", "quic"},
	"dtls":            {"tcp", "dtls"},
	"vless":           {"vless", "reality"},
	"vless+reality":   {"vless", "reality"},
	"reality":         {"vless", "reality"},
	"vless+tls":       {"vless", "tls"},
	"vmess":           {"vmess", "tcp"},
	"vmess+tls":       {"vmess", "tls"},
	"trojan":          {"trojan", "tls"},
	"trojan+tls":      {"trojan", "tls"},
	"ss":              {"ss", "tcp"},
	"shadowsocks":     {"ss", "tcp"},
	"ss+tls":          {"ss", "tls"},
	"shadowsocks+tls": {"ss", "tls"},
	"hysteria2":       {"hysteria2", "hysteria2"},
	"hy2":             {"hysteria2", "hysteria2"},
}

var suffixConnectors = map[string]string{
	"http":        "http",
	"socks5":      "socks5",
	"socks5h":     "socks5",
	"tcp":         "tcp",
	"vless":       "vless",
	"vmess":       "vmess",
	"trojan":      "trojan",
	"ss":          "ss",
	"shadowsocks": "ss",
}

func SplitTransport(raw string) (base string, transport TransportKind) {
	s := normalize(raw)
	if pair, ok := directTransports[s]; ok {
		return pair.base, pair.transport
	}
	for _, entry := range transportSuffixes {
		if b, found := strings.CutSuffix(s, entry.suffix); found {
			return b, entry.transport
		}
	}
	return s, TransportNone
}

func NormalizeProxy(raw string) ProxyTypes {
	base, transport := SplitTransport(raw)
	out := ProxyTypes{
		Handler:   base,
		Listener:  base,
		Transport: transport,
	}
	switch base {
	case "http3":
		out.Handler = "http"
		out.Listener = "http3"
		out.Transport = TransportNone
		return out
	case "http2":
		out.Handler = "http"
		out.Listener = "http2"
		out.Transport = TransportNone
		return out
	case "socks5h":
		out.Handler = "socks5"
	case "vless":
		out.Handler = "vless"
		out.Listener = "reality"
		out.Transport = TransportNone
		return out
	case "vmess":
		out.Handler = "vmess"
		out.Listener = "tcp"
	case "trojan":
		out.Handler = "trojan"
		out.Listener = "tcp"
	case "ss", "shadowsocks":
		out.Handler = "ss"
		out.Listener = "tcp"
	}

	switch transport {
	case TransportDTLS:
		out.Listener = "dtls"
	case TransportH2:
		out.Listener = "h2"
	case TransportH3:
		out.Listener = "h3"
	case TransportQUIC:
		out.Listener = "quic"
	}
	return out
}

func ResolveRouteTypes(raw string) (RouteTypes, error) {
	s := normalize(raw)
	if s == "" {
		return RouteTypes{}, fmt.Errorf("unsupported scheme: %s", s)
	}
	if pair, ok := routeTypes[s]; ok {
		return pair, nil
	}
	for _, entry := range transportSuffixes {
		base, found := strings.CutSuffix(s, entry.suffix)
		if !found || entry.transport == TransportNone {
			continue
		}
		connector, ok := suffixConnectors[base]
		if !ok {
			return RouteTypes{}, fmt.Errorf("unsupported scheme: %s", s)
		}
		return RouteTypes{Connector: connector, Dialer: string(entry.transport)}, nil
	}
	return RouteTypes{}, fmt.Errorf("unsupported scheme: %s", s)
}

func normalize(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}
