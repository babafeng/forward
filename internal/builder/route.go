package builder

import (
	"fmt"
	"strings"

	"forward/base/endpoint"
	"forward/internal/chain"
	"forward/internal/config"
	"forward/internal/connector"
	"forward/internal/dialer"
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
		if dialerName == "tls" || dialerName == "http3" || dialerName == "dtls" || dialerName == "http2" {
			tlsOpts := ctls.ClientOptions{}
			if dialerName == "http3" {
				tlsOpts.NextProtos = []string{"h3"}
			}
			if dialerName == "http2" {
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

		newConnector := registry.ConnectorRegistry().Get(connectorName)
		if newConnector == nil {
			return nil, fmt.Errorf("hop %d: connector %q not registered", i+1, connectorName)
		}
		c := newConnector(
			connector.AuthOption(hop.User),
			connector.TimeoutOption(cfg.HandshakeTimeout),
			connector.LoggerOption(cfg.Logger),
		)

		node := chain.NewNode(fmt.Sprintf("%s_%d", scheme, i+1), hop.Address(), chain.NewTransport(d, c))
		nodes = append(nodes, node)
	}

	return chain.NewRoute(nodes...), nil
}

func resolveTypes(scheme string) (connectorName, dialerName string, err error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		return "", "", fmt.Errorf("unsupported scheme: %s", scheme)
	}
	if scheme == "https" || scheme == "http+tls" {
		return "http", "tls", nil
	}
	if scheme == "http3" {
		return "http", "http3", nil
	}
	if scheme == "http2" {
		return "http", "http2", nil
	}
	if strings.HasSuffix(scheme, "+http2") {
		base := strings.TrimSuffix(scheme, "+http2")
		switch base {
		case "http":
			return "http", "http2", nil
		case "socks5", "socks5h":
			return "socks5", "http2", nil
		case "tcp":
			return "tcp", "http2", nil
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
	if scheme == "tls" {
		return "tcp", "tls", nil
	}
	if scheme == "dtls" {
		return "tcp", "dtls", nil
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
