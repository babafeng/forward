// Package trojan provides Trojan protocol outbound Connector support.
package trojan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	xtrojan "github.com/xtls/xray-core/proxy/trojan"

	ptrojan "forward/base/protocol/trojan"
	"forward/internal/connector"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.ConnectorRegistry().Register("trojan", NewConnector)
}

type Connector struct {
	account *xtrojan.MemoryAccount
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Connector{options: options}
}

func (c *Connector) Init(md metadata.Metadata) error {
	if md == nil {
		return fmt.Errorf("trojan connector requires metadata")
	}
	password := strings.TrimSpace(md.GetString(metadata.KeyPassword))
	if password == "" {
		return fmt.Errorf("trojan password is required")
	}
	user, err := ptrojan.CreateUser(password)
	if err != nil {
		return fmt.Errorf("create trojan user failed: %w", err)
	}
	account, ok := user.Account.(*xtrojan.MemoryAccount)
	if !ok {
		return fmt.Errorf("trojan account type is invalid")
	}
	c.account = account
	return nil
}

func (c *Connector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	if c.account == nil {
		return nil, fmt.Errorf("trojan connector not initialized")
	}
	dest, err := destination(network, address)
	if err != nil {
		return nil, err
	}

	connWriter := &xtrojan.ConnWriter{
		Writer:  conn,
		Target:  dest,
		Account: c.account,
	}
	var writer buf.Writer = connWriter
	var reader buf.Reader = buf.NewReader(conn)
	if dest.Network == xnet.Network_UDP {
		writer = &xtrojan.PacketWriter{Writer: connWriter, Target: dest}
		reader = &xtrojan.PacketReader{Reader: conn}
	}

	// Send the request header even when the caller waits for a response before
	// writing application payload.
	if _, err := connWriter.Write(nil); err != nil {
		return nil, fmt.Errorf("trojan request header failed: %w", err)
	}

	return &trojanConn{
		Conn:   conn,
		reader: &buf.BufferedReader{Reader: reader},
		writer: writer,
	}, nil
}

func destination(network, address string) (xnet.Destination, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("invalid target address %q: %w", address, err)
	}
	port, err := xnet.PortFromString(portStr)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("invalid target port %q: %w", portStr, err)
	}
	if strings.HasPrefix(strings.ToLower(network), "udp") {
		return xnet.UDPDestination(xnet.ParseAddress(host), port), nil
	}
	return xnet.TCPDestination(xnet.ParseAddress(host), port), nil
}

type trojanConn struct {
	net.Conn
	reader *buf.BufferedReader
	writer buf.Writer
	mu     sync.Mutex
}

func (c *trojanConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *trojanConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	written := 0
	for len(p) > 0 {
		b := buf.New()
		n, err := b.Write(p)
		if err != nil && n == 0 {
			b.Release()
			return written, err
		}
		p = p[n:]
		if err := c.writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}
