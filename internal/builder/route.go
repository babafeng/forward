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

		dialerOpts := []dialer.Option{
			dialer.TimeoutOption(cfg.DialTimeout),
			dialer.LoggerOption(cfg.Logger),
		}
		if dialerName == "tls" || dialerName == "http3" || dialerName == "h3" || dialerName == "dtls" || dialerName == "h2" {
			tlsOpts := ctls.ClientOptions{}
			if dialerName == "http3" || dialerName == "h3" {
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

		// 为 Reality Dialer 初始化 metadata
		if dialerName == "reality" {
			dmd := buildDialerMetadata(hop)
			if err := d.Init(dmd); err != nil {
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
			cmd := buildConnectorMetadata(hop)
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
	return metadata.New(map[string]any{
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
	})
}

// buildConnectorMetadata 为 VLESS Connector 构建 metadata
func buildConnectorMetadata(hop endpoint.Endpoint) metadata.Metadata {
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
