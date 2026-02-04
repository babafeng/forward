// Package vmess 提供 VMess 协议 Connector（出站）
package vmess

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess/encoding"

	pvmess "forward/base/protocol/vmess"
	"forward/internal/connector"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.ConnectorRegistry().Register("vmess", NewConnector)
}

// Connector VMess 协议 Connector
type Connector struct {
	user     *protocol.MemoryUser
	security protocol.SecurityType
	options  connector.Options
}

// NewConnector 创建新的 VMess Connector
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
		return fmt.Errorf("vmess connector requires metadata")
	}

	// 解析 UUID
	uuid := md.GetString(metadata.KeyUUID)
	if uuid == "" {
		return fmt.Errorf("vmess uuid is required")
	}

	// 获取 alterID
	alterID := md.GetInt(metadata.KeyAlterID)

	// 获取加密类型
	security := pvmess.ParseSecurityType(md.GetString(metadata.KeySecurity))

	// 创建用户
	user, err := pvmess.CreateUser(pvmess.UserConfig{
		UUID:     uuid,
		AlterID:  alterID,
		Security: security,
	})
	if err != nil {
		return fmt.Errorf("create vmess user failed: %w", err)
	}

	c.user = user

	// 保存 security 类型，AUTO 转换为 AES-128-GCM
	c.security = security.ToXraySecurity()
	if c.security == protocol.SecurityType_AUTO {
		c.security = protocol.SecurityType_AES128_GCM
	}

	return nil
}

func (c *Connector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	if c.user == nil {
		return nil, fmt.Errorf("vmess user not initialized")
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid target address %q: %w", address, err)
	}

	port, err := xnet.PortFromString(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid target port %q: %w", portStr, err)
	}

	command := protocol.RequestCommandTCP
	if network == "udp" {
		command = protocol.RequestCommandUDP
	}

	// 构建请求头
	request := &protocol.RequestHeader{
		Version:  encoding.Version,
		User:     c.user,
		Command:  command,
		Address:  xnet.ParseAddress(host),
		Port:     port,
		Security: c.security,
		Option:   protocol.RequestOptionChunkStream | protocol.RequestOptionChunkMasking,
	}

	// 创建客户端会话 (behaviorSeed 设为当前时间戳)
	session := encoding.NewClientSession(ctx, time.Now().UnixNano())

	// 编码请求头
	if err := session.EncodeRequestHeader(request, conn); err != nil {
		return nil, fmt.Errorf("vmess encode request header failed: %w", err)
	}

	// 创建请求体编码器
	bodyWriter, err := session.EncodeRequestBody(request, conn)
	if err != nil {
		return nil, fmt.Errorf("vmess encode request body failed: %w", err)
	}

	return &vmessConn{
		Conn:       conn,
		session:    session,
		request:    request,
		bodyWriter: bodyWriter,
		reader:     nil,
	}, nil
}

// vmessConn 封装 VMess 连接
type vmessConn struct {
	net.Conn
	session    *encoding.ClientSession
	request    *protocol.RequestHeader
	bodyWriter buf.Writer
	reader     buf.Reader

	initOnce sync.Once
	initErr  error
}

func (c *vmessConn) Read(p []byte) (int, error) {
	if err := c.initReader(); err != nil {
		return 0, err
	}

	// 使用 buf.Reader 读取
	mb, err := c.reader.ReadMultiBuffer()
	if err != nil {
		return 0, err
	}

	n := 0
	for _, b := range mb {
		copied := copy(p[n:], b.Bytes())
		n += copied
		b.Release()
		if n >= len(p) {
			break
		}
	}
	return n, nil
}

func (c *vmessConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	written := 0
	for len(p) > 0 {
		b := buf.New()
		n, err := b.Write(p)
		if err != nil && n == 0 {
			b.Release()
			return written, err
		}
		p = p[n:]
		if err := c.bodyWriter.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

func (c *vmessConn) initReader() error {
	c.initOnce.Do(func() {
		// 解码响应头
		if _, err := c.session.DecodeResponseHeader(c.Conn); err != nil {
			c.initErr = fmt.Errorf("vmess decode response header failed: %w", err)
			return
		}

		// 创建响应体解码器
		bodyReader, err := c.session.DecodeResponseBody(c.request, c.Conn)
		if err != nil {
			c.initErr = fmt.Errorf("vmess decode response body failed: %w", err)
			return
		}
		c.reader = bodyReader
	})
	return c.initErr
}

func (c *vmessConn) Close() error {
	// 发送关闭信号
	if c.bodyWriter != nil {
		_ = c.bodyWriter.WriteMultiBuffer(nil)
	}
	return c.Conn.Close()
}

// ReadFrom 实现 io.ReaderFrom
func (c *vmessConn) ReadFrom(r io.Reader) (int64, error) {
	var total int64
	buf := make([]byte, 32*1024)
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
func (c *vmessConn) WriteTo(w io.Writer) (int64, error) {
	if err := c.initReader(); err != nil {
		return 0, err
	}
	var total int64
	b := make([]byte, 32*1024)
	for {
		n, err := c.Read(b)
		if n > 0 {
			wn, werr := w.Write(b[:n])
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
