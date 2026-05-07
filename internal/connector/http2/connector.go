package http2

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/http2"

	"forward/internal/connector"
	"forward/internal/connector/shared"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.ConnectorRegistry().Register("http2", NewConnector)
}

type Connector struct {
	shared.Config
}

func NewConnector(opts ...connector.Option) connector.Connector {
	return &Connector{Config: shared.NewConfig(opts...)}
}

func (c *Connector) Init(_ metadata.Metadata) error {
	return nil
}

func (c *Connector) Connect(ctx context.Context, conn net.Conn, network, address string, _ ...connector.ConnectOption) (net.Conn, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	switch {
	case strings.HasPrefix(network, "tcp"):
	case strings.HasPrefix(network, "udp"):
	default:
		return nil, fmt.Errorf("http2 connector supports tcp/udp only")
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("http2 connector requires tls connection")
	}
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		return nil, fmt.Errorf("http2 connector requires h2")
	}

	t := &http2.Transport{}
	cc, err := t.NewClientConn(tlsConn)
	if err != nil {
		return nil, err
	}
	return c.dialH2(ctx, cc, network, address)
}

func (c *Connector) dialH2(ctx context.Context, cc *http2.ClientConn, network, address string) (net.Conn, error) {
	return shared.DialHTTP2(ctx, cc, network, address, c.AuthVal, "http2")
}
