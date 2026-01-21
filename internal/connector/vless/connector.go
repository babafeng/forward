// Package vless 提供 VLESS 协议 Connector
package vless

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	xuuid "github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy"
	xvless "github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"

	pvless "forward/base/protocol/vless"
	"forward/internal/connector"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.ConnectorRegistry().Register("vless", NewConnector)
}

type Connector struct {
	userID     *protocol.ID
	flow       string
	encryption string
	options    connector.Options
}

// NewConnector 创建新的 VLESS Connector
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
		return fmt.Errorf("vless connector requires metadata")
	}

	// 解析 UUID
	uuidStr := md.GetString(metadata.KeyUUID)
	if uuidStr == "" {
		return fmt.Errorf("vless uuid is required")
	}

	uuid, err := pvless.ParseUUID(uuidStr)
	if err != nil {
		return fmt.Errorf("invalid vless uuid: %w", err)
	}

	parsedUUID, err := xuuid.ParseBytes(uuid[:])
	if err != nil {
		return fmt.Errorf("invalid vless uuid: %w", err)
	}

	c.userID = protocol.NewID(parsedUUID)
	c.flow = strings.TrimSpace(md.GetString(metadata.KeyFlow))
	c.encryption = strings.TrimSpace(md.GetString(metadata.KeyEncryption))

	return nil
}

func (c *Connector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	request, requestAddons, err := c.buildRequest(network, address)
	if err != nil {
		return nil, err
	}

	trafficState := proxy.NewTrafficState(c.userID.Bytes())
	bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))

	if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
		return nil, fmt.Errorf("vless request encode failed: %w", err)
	}

	clientWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, nil)

	// Vision 流需要发送初始 padding
	if requestAddons.Flow == xvless.XRV {
		if err := clientWriter.WriteMultiBuffer(make(buf.MultiBuffer, 1)); err != nil {
			return nil, fmt.Errorf("vless vision padding failed: %w", err)
		}
	}

	if err := bufferWriter.SetBuffered(false); err != nil {
		return nil, fmt.Errorf("vless flush failed: %w", err)
	}

	return &vlessConn{
		Conn:   conn,
		reader: nil,
		writer: clientWriter,
		ctx:    ctx,
		req:    request,
		addons: requestAddons,
		state:  trafficState,
	}, nil
}

func (c *Connector) buildRequest(network, address string) (*protocol.RequestHeader, *encoding.Addons, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid target address %q: %w", address, err)
	}

	port, err := xnet.PortFromString(portStr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid target port %q: %w", portStr, err)
	}

	command := protocol.RequestCommandTCP
	if strings.HasPrefix(strings.ToLower(network), "udp") {
		command = protocol.RequestCommandUDP
	}

	flow := c.flow
	allowUDP443 := false
	if flow == xvless.XRV+"-udp443" {
		allowUDP443 = true
		flow = xvless.XRV
	}

	// Vision 不支持 UDP（除非是 UDP443）
	if flow == xvless.XRV && command == protocol.RequestCommandUDP {
		if !allowUDP443 || port != 443 {
			return nil, nil, fmt.Errorf("xtls-rprx-vision does not support udp")
		}
	}

	encryption := c.encryption
	if encryption == "" {
		encryption = "none"
	}

	user := &protocol.MemoryUser{
		Account: &xvless.MemoryAccount{
			ID:         c.userID,
			Flow:       flow,
			Encryption: encryption,
		},
	}

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    user,
		Command: command,
		Address: xnet.ParseAddress(host),
		Port:    port,
	}

	addons := &encoding.Addons{Flow: flow}
	return request, addons, nil
}

// vlessConn 封装 VLESS 连接
type vlessConn struct {
	net.Conn
	reader *buf.BufferedReader
	writer buf.Writer

	ctx    context.Context
	req    *protocol.RequestHeader
	addons *encoding.Addons
	state  *proxy.TrafficState

	initOnce     sync.Once
	initErr      error
	directReader bool
}

func (c *vlessConn) Read(p []byte) (int, error) {
	if err := c.initReader(); err != nil {
		return 0, err
	}

	// Vision 流直接读取优化
	if c.state != nil && c.state.Outbound.DownlinkReaderDirectCopy && !c.directReader {
		rawConn, _, _ := proxy.UnwrapRawConn(c.Conn)
		c.reader = &buf.BufferedReader{Reader: buf.NewReader(rawConn)}
		c.directReader = true
	}

	return c.reader.Read(p)
}

func (c *vlessConn) Write(p []byte) (int, error) {
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
		if err := c.writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

func (c *vlessConn) initReader() error {
	c.initOnce.Do(func() {
		responseAddons, err := encoding.DecodeResponseHeader(c.Conn, c.req)
		if err != nil {
			c.initErr = fmt.Errorf("vless response decode failed: %w", err)
			return
		}

		reader := encoding.DecodeBodyAddons(c.Conn, c.req, responseAddons)

		// 处理 Vision 流
		if c.addons != nil && c.addons.Flow == xvless.XRV {
			input, rawInput, err := visionInputBuffers(c.Conn)
			if err != nil {
				c.initErr = err
				return
			}
			reader = proxy.NewVisionReader(reader, c.state, false, c.ctx, c.Conn, input, rawInput, nil)
		}

		c.reader = &buf.BufferedReader{Reader: reader}
	})
	return c.initErr
}

// visionInputBuffers 获取 Vision 流所需的输入缓冲区
func visionInputBuffers(conn net.Conn) (*bytes.Reader, *bytes.Buffer, error) {
	if statConn, ok := conn.(*stat.CounterConnection); ok {
		conn = statConn.Connection
	}

	switch c := conn.(type) {
	case *tls.Conn:
		if c.ConnectionState().Version != gotls.VersionTLS13 {
			return nil, nil, fmt.Errorf("xtls-rprx-vision requires TLS 1.3")
		}
		return xtlsBuffers(c.Conn)
	case *tls.UConn:
		if c.ConnectionState().Version != gotls.VersionTLS13 {
			return nil, nil, fmt.Errorf("xtls-rprx-vision requires TLS 1.3")
		}
		if c.UConn == nil || c.UConn.Conn == nil {
			return nil, nil, fmt.Errorf("xtls-rprx-vision requires valid tls uconn")
		}
		return xtlsBuffers(c.UConn.Conn)
	case *reality.UConn:
		if c.UConn == nil || c.UConn.Conn == nil {
			return nil, nil, fmt.Errorf("xtls-rprx-vision requires valid reality uconn")
		}
		return xtlsBuffers(c.UConn.Conn)
	case *reality.Conn:
		return xtlsBuffers(c)
	default:
		return nil, nil, fmt.Errorf("xtls-rprx-vision requires TLS or REALITY")
	}
}

// xtlsBuffers 通过反射获取 xtls 内部缓冲区
func xtlsBuffers(conn any) (*bytes.Reader, *bytes.Buffer, error) {
	val := reflect.ValueOf(conn)
	if val.Kind() != reflect.Ptr || val.IsNil() {
		return nil, nil, fmt.Errorf("invalid xtls connection")
	}

	t := val.Type().Elem()
	inputField, ok := t.FieldByName("input")
	if !ok {
		return nil, nil, fmt.Errorf("missing xtls input buffer")
	}

	rawInputField, ok := t.FieldByName("rawInput")
	if !ok {
		return nil, nil, fmt.Errorf("missing xtls rawInput buffer")
	}

	if inputField.Type != reflect.TypeOf(bytes.Reader{}) {
		return nil, nil, fmt.Errorf("xtls input field type mismatch: expected bytes.Reader, got %v", inputField.Type)
	}
	if rawInputField.Type != reflect.TypeOf(bytes.Buffer{}) {
		return nil, nil, fmt.Errorf("xtls rawInput field type mismatch: expected bytes.Buffer, got %v", rawInputField.Type)
	}

	p := unsafe.Pointer(val.Pointer())
	input := (*bytes.Reader)(unsafe.Pointer(uintptr(p) + inputField.Offset))
	rawInput := (*bytes.Buffer)(unsafe.Pointer(uintptr(p) + rawInputField.Offset))

	if input == nil || rawInput == nil {
		return nil, nil, fmt.Errorf("xtls input buffers not initialized")
	}

	return input, rawInput, nil
}
