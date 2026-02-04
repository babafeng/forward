package builder

import (
	"fmt"
	"strings"

	"forward/base/endpoint"
	"forward/internal/chain"
	"forward/internal/config"
	"forward/internal/connector"
	"forward/internal/dialer"
	"forward/internal/metadata"
	"forward/internal/registry"

	ctls "forward/internal/config/tls"
)

func BuildRoute(cfg config.Config, hops []endpoint.Endpoint) (chain.Route, error) {
	if len(hops) == 0 {
		return chain.NewRoute(), nil
	}

	nodes := make([]*chain.Node, 0, len(hops))
	for i, hop := range hops {
		scheme := strings.ToLower(strings.TrimSpace(hop.Scheme))

		connectorName, dialerName, err := resolveTypes(scheme)
		if err != nil {
			return nil, fmt.Errorf("hop %d: %w", i+1, err)
		}

		// VMess: check if using WebSocket transport
		if connectorName == "vmess" {
			q := hop.Query
			// vmess://...?obfs=websocket or ...?type=ws or ...?net=ws
			if strings.EqualFold(q.Get("obfs"), "websocket") || strings.EqualFold(q.Get("type"), "ws") || strings.EqualFold(q.Get("net"), "ws") {
				dialerName = "ws"
			}
		}

		dialerOpts := []dialer.Option{
			dialer.TimeoutOption(cfg.DialTimeout),
			dialer.LoggerOption(cfg.Logger),
		}
		if dialerName == "tls" || dialerName == "http3" || dialerName == "h3" || dialerName == "dtls" || dialerName == "h2" || dialerName == "quic" {
			tlsOpts := ctls.ClientOptions{}
			if dialerName == "http3" || dialerName == "h3" || dialerName == "quic" {
				tlsOpts.NextProtos = []string{"h3"} // QUIC typically uses h3 ALPN or similar, but for raw quic maybe empty or custom?
				// Wait, if it's raw QUIC, does it default to 'h3'?
				// The quic listener implementation might set NextProtos.
				// Let's check quic listener. But generally, for quic-go, ALPN is needed.
				// Assuming 'h3' for now as it was aliased to http3 before, or maybe no ALPN?
				// quic-go requires ALPN to match.
				// Let's check internal/listener/quic/listener.go to see what ALPN it expects.
				tlsOpts.NextProtos = []string{"h3"}
			}
			if dialerName == "h2" {
				tlsOpts.NextProtos = []string{"h2"}
			}
			if connectorName == "http2" {
				tlsOpts.NextProtos = []string{"h2"}
			}
			if dialerName == "tls" && connectorName == "http" {
				tlsOpts.NextProtos = []string{"h2", "http/1.1"}
			}
			tlsCfg, err := ctls.ClientConfig(hop, cfg.Insecure, tlsOpts)
			if err != nil {
				return nil, fmt.Errorf("hop %d: tls config: %w", i+1, err)
			}
			dialerOpts = append(dialerOpts, dialer.TLSConfigOption(tlsCfg))
		}

		newDialer := registry.DialerRegistry().Get(dialerName)
		if newDialer == nil {
			return nil, fmt.Errorf("hop %d: dialer %q not registered", i+1, dialerName)
		}
		d := newDialer(dialerOpts...)

		// Dialer 初始化：Reality / H2 / H3 / WS 需要 metadata
		if dialerName == "reality" || dialerName == "h2" || dialerName == "h3" {
			dmd := buildDialerMetadata(hop)
			if err := d.Init(dmd); err != nil {
				return nil, fmt.Errorf("hop %d: init dialer: %w", i+1, err)
			}
		} else if dialerName == "ws" {
			dmd := buildWSDialerMetadata(hop)
			if err := d.Init(dmd); err != nil {
				return nil, fmt.Errorf("hop %d: init dialer: %w", i+1, err)
			}
		} else {
			if err := d.Init(nil); err != nil {
				return nil, fmt.Errorf("hop %d: init dialer: %w", i+1, err)
			}
		}

		newConnector := registry.ConnectorRegistry().Get(connectorName)
		if newConnector == nil {
			return nil, fmt.Errorf("hop %d: connector %q not registered", i+1, connectorName)
		}
		c := newConnector(
			connector.AuthOption(hop.User),
			connector.TimeoutOption(cfg.HandshakeTimeout),
			connector.LoggerOption(cfg.Logger),
		)

		// 为 VLESS Connector 初始化 metadata
		if connectorName == "vless" {
			cmd := buildVlessConnectorMetadata(hop)
			if err := c.Init(cmd); err != nil {
				return nil, fmt.Errorf("hop %d: init connector: %w", i+1, err)
			}
		}

		// 为 VMess Connector 初始化 metadata
		if connectorName == "vmess" {
			cmd := buildVmessConnectorMetadata(hop)
			if err := c.Init(cmd); err != nil {
				return nil, fmt.Errorf("hop %d: init connector: %w", i+1, err)
			}
		}

		node := chain.NewNode(fmt.Sprintf("%s_%d", scheme, i+1), hop.Address(), chain.NewTransport(d, c))
		nodes = append(nodes, node)
	}

	return chain.NewRoute(nodes...), nil
}

// buildDialerMetadata 为 Reality Dialer 构建 metadata
func buildDialerMetadata(hop endpoint.Endpoint) metadata.Metadata {
	q := hop.Query
	mdMap := map[string]any{
		metadata.KeyHost:        hop.Host,
		metadata.KeyPort:        hop.Port,
		metadata.KeySecurity:    q.Get("security"),
		metadata.KeyNetwork:     q.Get("type"),
		metadata.KeySNI:         q.Get("sni"),
		metadata.KeyFingerprint: q.Get("fp"),
		metadata.KeyPublicKey:   q.Get("pbk"),
		metadata.KeyShortID:     q.Get("sid"),
		metadata.KeySpiderX:     q.Get("spiderx"),
		metadata.KeyALPN:        q.Get("alpn"),
		metadata.KeyInsecure:    q.Get("insecure") == "true" || q.Get("insecure") == "1",
	}
	if hop.User != nil {
		if p, ok := hop.User.Password(); ok {
			mdMap["secret"] = p
		}
	}
	return metadata.New(mdMap)
}

// buildVlessConnectorMetadata 为 VLESS Connector 构建 metadata
func buildVlessConnectorMetadata(hop endpoint.Endpoint) metadata.Metadata {
	q := hop.Query
	uuid := ""
	if hop.User != nil {
		uuid = hop.User.Username()
	}
	return metadata.New(map[string]any{
		metadata.KeyUUID:       uuid,
		metadata.KeyFlow:       q.Get("flow"),
		metadata.KeyEncryption: q.Get("encryption"),
	})
}

// buildVmessConnectorMetadata 为 VMess Connector 构建 metadata
// URL 格式: vmess://security:uuid@host:port?alterId=0
func buildVmessConnectorMetadata(hop endpoint.Endpoint) metadata.Metadata {
	q := hop.Query
	uuid := ""
	security := ""
	if hop.User != nil {
		security = hop.User.Username() // 加密方式在用户名
		if p, ok := hop.User.Password(); ok {
			uuid = p // UUID 在密码
		}
	}
	return metadata.New(map[string]any{
		metadata.KeyUUID:     uuid,
		metadata.KeySecurity: security,
		metadata.KeyAlterID:  q.Get("alterId"),
	})
}

func buildWSDialerMetadata(hop endpoint.Endpoint) metadata.Metadata {
	q := hop.Query
	mdMap := map[string]any{
		metadata.KeyHost:     q.Get("host"),
		metadata.KeyPath:     q.Get("path"),
		metadata.KeySecurity: q.Get("security"), // e.g. "tls"
		metadata.KeyInsecure: q.Get("insecure") == "true" || q.Get("insecure") == "1",
	}
	// Also fallback to endpoint host if "host" not in query?
	// VMess "sni" query often used for TLS SNI, and "host" for WS Host header.
	// If "host" query is missing, maybe default to hop.Host if they differ?
	// Usually for VMess, hop.Host is the server IP, and SNI/Host is for obfuscation.
	return metadata.New(mdMap)
}

func resolveTypes(scheme string) (connectorName, dialerName string, err error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		return "", "", fmt.Errorf("unsupported scheme: %s", scheme)
	}
	if scheme == "https" || scheme == "http+tls" {
		return "http", "tls", nil
	}
	if scheme == "http2" {
		return "http2", "tls", nil
	}
	if scheme == "http3" {
		return "http3", "http3", nil
	}
	if scheme == "quic" {
		return "tcp", "quic", nil
	}
	if scheme == "tls" {
		return "http", "tls", nil
	}
	if scheme == "h2" {
		return "http", "h2", nil
	}
	if scheme == "h3" {
		return "http", "h3", nil
	}
	if strings.HasSuffix(scheme, "+h2") {
		base := strings.TrimSuffix(scheme, "+h2")
		switch base {
		case "http":
			return "http", "h2", nil
		case "socks5", "socks5h":
			return "socks5", "h2", nil
		case "tcp":
			return "tcp", "h2", nil
		default:
			return "", "", fmt.Errorf("unsupported scheme: %s", scheme)
		}
	}
	if strings.HasSuffix(scheme, "+h3") {
		base := strings.TrimSuffix(scheme, "+h3")
		switch base {
		case "http":
			return "http", "h3", nil
		case "socks5", "socks5h":
			return "socks5", "h3", nil
		case "tcp":
			return "tcp", "h3", nil
		default:
			return "", "", fmt.Errorf("unsupported scheme: %s", scheme)
		}
	}
	if strings.HasSuffix(scheme, "+dtls") {
		base := strings.TrimSuffix(scheme, "+dtls")
		switch base {
		case "http":
			return "http", "dtls", nil
		case "socks5", "socks5h":
			return "socks5", "dtls", nil
		case "tcp":
			return "tcp", "dtls", nil
		default:
			return "", "", fmt.Errorf("unsupported scheme: %s", scheme)
		}
	}
	if strings.HasSuffix(scheme, "+tls") {
		base := strings.TrimSuffix(scheme, "+tls")
		switch base {
		case "http":
			return "http", "tls", nil
		case "socks5", "socks5h":
			return "socks5", "tls", nil
		case "tcp":
			return "tcp", "tls", nil
		default:
			return "", "", fmt.Errorf("unsupported scheme: %s", scheme)
		}
	}
	if strings.HasSuffix(scheme, "+quic") {
		base := strings.TrimSuffix(scheme, "+quic")
		switch base {
		case "http":
			return "http", "quic", nil
		case "socks5", "socks5h":
			return "socks5", "quic", nil
		case "tcp":
			return "tcp", "quic", nil
		default:
			return "", "", fmt.Errorf("unsupported scheme: %s", scheme)
		}
	}
	if scheme == "dtls" {
		return "tcp", "dtls", nil
	}

	// VLESS + Reality 支持
	if scheme == "vless" || scheme == "vless+reality" || scheme == "reality" {
		return "vless", "reality", nil
	}
	if scheme == "vless+tls" {
		return "vless", "tls", nil
	}

	// VMess 支持
	if scheme == "vmess" {
		return "vmess", "tcp", nil
	}
	if scheme == "vmess+tls" {
		return "vmess", "tls", nil
	}

	switch scheme {
	case "http":
		return "http", "tcp", nil
	case "socks5", "socks5h":
		return "socks5", "tcp", nil
	case "tcp":
		return "tcp", "tcp", nil
	default:
		return "", "", fmt.Errorf("unsupported scheme: %s", scheme)
	}
}
