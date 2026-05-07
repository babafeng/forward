package http3

import (
	"context"
	"fmt"
	"net"
	stdhttp "net/http"

	"forward/internal/connector"
	"forward/internal/connector/shared"
	"forward/internal/metadata"
	"forward/internal/registry"
)

type clientProvider interface {
	HTTPClient() *stdhttp.Client
}

func init() {
	registry.ConnectorRegistry().Register("http3", NewConnector)
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
	clientConn, ok := conn.(clientProvider)
	if !ok {
		return nil, fmt.Errorf("http3 connector requires http3 dialer connection")
	}
	client := clientConn.HTTPClient()
	if client == nil {
		return nil, fmt.Errorf("http3 connector missing client")
	}

	switch {
	case shared.IsTCP(network):
	case shared.IsUDP(network):
	default:
		return nil, fmt.Errorf("http3 connector supports tcp/udp only")
	}

	proxyAddr := ""
	if ra := conn.RemoteAddr(); ra != nil {
		proxyAddr = ra.String()
	}
	if proxyAddr == "" {
		return nil, fmt.Errorf("http3 connector missing proxy address")
	}

	return shared.DialHTTPClient(ctx, client, "https://"+proxyAddr, network, address, c.AuthVal, "http3")
}
