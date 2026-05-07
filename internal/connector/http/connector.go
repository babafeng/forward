package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"forward/internal/connector"
	"forward/internal/connector/shared"
	"forward/internal/handler/udptun"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.ConnectorRegistry().Register("http", NewConnector)
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
		return nil, fmt.Errorf("http connector supports tcp/udp only")
	}

	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if state.NegotiatedProtocol == "h2" {
			t := &http2.Transport{}
			cc, err := t.NewClientConn(tlsConn)
			if err != nil {
				return nil, err
			}
			return c.dialH2(ctx, cc, network, address)
		}
	}

	return c.dialHTTP1(ctx, conn, network, address)
}

func (c *Connector) dialHTTP1(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error) {
	if deadline := shared.DeadlineFromContext(ctx, c.Timeout); !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address)
	if shared.IsUDP(network) {
		req += "X-Forward-Protocol: udp\r\n"
	}
	if c.AuthVal != "" {
		req += fmt.Sprintf("Proxy-Authorization: %s\r\n", c.AuthVal)
	}
	req += "\r\n"

	if _, err := io.WriteString(conn, req); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := stdhttp.ReadResponse(br, &stdhttp.Request{Method: stdhttp.MethodConnect})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != stdhttp.StatusOK {
		return nil, fmt.Errorf("http proxy connect failed: %s", resp.Status)
	}

	_ = conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		conn = &readWriteConn{Conn: conn, r: br}
	}
	if shared.IsUDP(network) {
		udpAddr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, err
		}
		return udptun.ClientConn(conn, udpAddr), nil
	}
	return conn, nil
}

func (c *Connector) dialH2(ctx context.Context, cc *http2.ClientConn, network, address string) (net.Conn, error) {
	return shared.DialHTTP2(ctx, cc, network, address, c.AuthVal, "http2")
}

type readWriteConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readWriteConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
