// Package ss 提供 Shadowsocks 2022 协议 Connector（出站）
package ss

import (
	"context"
	"fmt"
	"io"
	"net"

	shadowsocks "github.com/sagernet/sing-shadowsocks"
	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	pss "forward/base/protocol/shadowsocks"
	"forward/internal/connector"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.ConnectorRegistry().Register("ss", NewConnector)
}

// Connector Shadowsocks 2022 协议 Connector
type Connector struct {
	method     shadowsocks.Method
	methodName string
	options    connector.Options
}

// NewConnector 创建新的 Shadowsocks Connector
func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &Connector{
		options: options,
	}
}

func (c *Connector) Init(md metadata.Metadata) error {
	if md == nil {
		return fmt.Errorf("shadowsocks connector requires metadata")
	}

	// 获取加密方法
	method := md.GetString(metadata.KeyMethod)
	if method == "" {
		return fmt.Errorf("shadowsocks method is required")
	}

	// 获取密码
	password := md.GetString(metadata.KeyPassword)
	if password == "" {
		return fmt.Errorf("shadowsocks password is required")
	}

	// 创建 Method 实例
	m, err := pss.NewMethod(method, password)
	if err != nil {
		return fmt.Errorf("create shadowsocks method failed: %w", err)
	}

	c.method = m
	c.methodName = method
	c.options.Logger.Debug("SS connector initialized with method %s", method)
	return nil
}

func (c *Connector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	if c.method == nil {
		return nil, fmt.Errorf("shadowsocks method not initialized")
	}

	// 解析目标地址
	dest := M.ParseSocksaddr(address)
	if !dest.IsValid() {
		return nil, fmt.Errorf("invalid target address %q", address)
	}

	c.options.Logger.Debug("SS connect %s -> %s (%s)", conn.RemoteAddr(), address, network)

	// TCP 使用 DialEarlyConn（支持 0-RTT）
	if network == "tcp" {
		return c.method.DialEarlyConn(conn, dest), nil
	}

	// UDP 使用 DialPacketConn 并封装
	if network == "udp" {
		packetConn := c.method.DialPacketConn(conn)
		return &ssPacketConn{
			Conn:       conn,
			packetConn: packetConn,
			dest:       dest,
		}, nil
	}

	return nil, fmt.Errorf("unsupported network: %s", network)
}



// ssPacketConn 封装 Shadowsocks UDP 连接
type ssPacketConn struct {
	net.Conn
	packetConn interface {
		WritePacket(buffer *B.Buffer, destination M.Socksaddr) error
		ReadPacket(buffer *B.Buffer) (M.Socksaddr, error)
	}
	dest M.Socksaddr
}

func (c *ssPacketConn) Read(p []byte) (int, error) {
	buffer := B.With(p)
	_, err := c.packetConn.ReadPacket(buffer)
	if err != nil {
		return 0, err
	}
	return buffer.Len(), nil
}

func (c *ssPacketConn) Write(p []byte) (int, error) {
	buffer := B.As(p)
	if err := c.packetConn.WritePacket(buffer, c.dest); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFrom 实现 io.ReaderFrom
func (c *ssPacketConn) ReadFrom(r io.Reader) (int64, error) {
	var total int64
	buf := make([]byte, 64*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			wn, werr := c.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

// WriteTo 实现 io.WriterTo
func (c *ssPacketConn) WriteTo(w io.Writer) (int64, error) {
	var total int64
	buf := make([]byte, 64*1024)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			wn, werr := w.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}
