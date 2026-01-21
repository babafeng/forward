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
	rev "forward/internal/reverse"

	ctls "forward/internal/config/tls"
)

func BuildReverseRoute(cfg config.Config, hops []endpoint.Endpoint) (chain.Route, error) {
	if len(hops) == 0 {
		return nil, fmt.Errorf("reverse forward requires at least one hop")
	}

	nodes := make([]*chain.Node, 0, len(hops))
	lastIdx := len(hops) - 1

	for i, hop := range hops {
		scheme := strings.ToLower(strings.TrimSpace(hop.Scheme))
		isLast := i == lastIdx

		connectorName, dialerName, err := resolveTypes(scheme)
		if err != nil {
			return nil, fmt.Errorf("hop %d: %w", i+1, err)
		}
		if isLast {
			connectorName, dialerName, err = resolveReverseTypes(scheme)
			if err != nil {
				return nil, fmt.Errorf("hop %d: %w", i+1, err)
			}
		}

		dialerOpts := []dialer.Option{
			dialer.TimeoutOption(cfg.DialTimeout),
			dialer.LoggerOption(cfg.Logger),
		}

		if needTLSConfigForReverse(isLast, scheme, dialerName) {
			tlsOpts := ctls.ClientOptions{}
			if isLast {
				if protos := rev.NextProtosForScheme(scheme); len(protos) > 0 {
					tlsOpts.NextProtos = protos
				}
			} else {
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

		if dialerName == "reality" {
			dmd := buildDialerMetadata(hop)
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

func resolveReverseTypes(scheme string) (connectorName, dialerName string, err error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	switch scheme {
	case "tls", "https":
		return "tcp", "tls", nil
	case "quic", "http3":
		return "tcp", "quic", nil
	case "reality", "vless+reality":
		return "vless", "reality", nil
	case "tcp":
		return "tcp", "tcp", nil
	default:
		return "", "", fmt.Errorf("unsupported reverse scheme: %s", scheme)
	}
}

func needTLSConfigForReverse(isLast bool, scheme, dialerName string) bool {
	if isLast {
		switch dialerName {
		case "tls", "quic":
			return true
		default:
			return false
		}
	}
	switch dialerName {
	case "tls", "http3", "h3", "dtls", "h2":
		return true
	default:
		return false
	}
}
