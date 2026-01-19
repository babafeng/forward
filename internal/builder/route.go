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
		if dialerName == "tls" {
			tlsCfg, err := ctls.ClientConfig(hop, cfg.Insecure, ctls.ClientOptions{})
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
	switch scheme {
	case "http":
		return "http", "tcp", nil
	case "https":
		return "http", "tls", nil
	case "socks5", "socks5h":
		return "socks5", "tcp", nil
	default:
		return "", "", fmt.Errorf("unsupported scheme: %s", scheme)
	}
}
