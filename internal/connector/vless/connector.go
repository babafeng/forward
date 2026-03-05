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
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xmux "github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	xuuid "github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy"
	xvless "github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"

	pvless "forward/base/protocol/vless"
	"forward/internal/connector"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.ConnectorRegistry().Register("vless", NewConnector)
}

const (
	defaultMuxMaxStreams = 16
	defaultMuxIdle       = 120 * time.Second
	muxCoolDomain        = "v1.mux.cool"
	muxCoolPort          = 9527
)

type Connector struct {
	userID     *protocol.ID
	flow       string
	encryption string
	mux        bool
	muxMax     int
	muxIdle    time.Duration
	options    connector.Options

	muxMu       sync.Mutex
	muxWorkers  []*vlessMuxWorker
	muxDisabled atomic.Bool
}

type vlessMuxWorker struct {
	worker   *xmux.ClientWorker
	lastUsed atomic.Int64
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
	c.mux = md.GetBool(metadata.KeyMux)
	c.muxMax = md.GetInt(metadata.KeyMuxMax)
	if v := md.Get(metadata.KeyMuxIdle); v != nil {
		if d, ok := v.(time.Duration); ok && d > 0 {
			c.muxIdle = d
		}
	}
	if c.mux {
		if c.muxMax <= 0 {
			c.muxMax = defaultMuxMaxStreams
		}
		if c.muxIdle <= 0 {
			c.muxIdle = defaultMuxIdle
		}
	}
	if c.mux && c.options.Logger != nil {
		c.options.Logger.Info("VLESS mux enabled: max_streams=%d idle=%s", c.muxMax, c.muxIdle)
	}

	return nil
}

func (c *Connector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	if c.mux && !c.muxDisabled.Load() {
		muxConn, consumed, err := c.connectMux(ctx, conn, network, address)
		if err == nil {
			return muxConn, nil
		}
		c.disableMux(err)
		if consumed {
			return nil, err
		}
	}
	return c.connectDirect(ctx, conn, network, address)
}

func (c *Connector) connectDirect(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error) {
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

func (c *Connector) connectMux(ctx context.Context, conn net.Conn, network, address string) (net.Conn, bool, error) {
	for _, w := range c.snapshotMuxWorkers() {
		streamConn, err := c.dispatchMuxStream(ctx, w.worker, network, address)
		if err == nil {
			w.touch()
			_ = conn.Close()
			return streamConn, false, nil
		}
	}

	w, err := c.createMuxWorker(ctx, conn)
	if err != nil {
		return nil, true, fmt.Errorf("vless mux bootstrap failed: %w", err)
	}
	c.addMuxWorker(w)

	streamConn, err := c.dispatchMuxStream(ctx, w.worker, network, address)
	if err != nil {
		_ = w.worker.Close()
		c.removeMuxWorker(w.worker)
		return nil, true, fmt.Errorf("vless mux dispatch failed: %w", err)
	}
	w.touch()
	return streamConn, true, nil
}

func (c *Connector) disableMux(reason error) {
	if !c.muxDisabled.CompareAndSwap(false, true) {
		return
	}
	if c.options.Logger != nil {
		c.options.Logger.Warn("VLESS mux disabled, fallback to direct forwarding: %v", reason)
	}
	c.muxMu.Lock()
	workers := c.muxWorkers
	c.muxWorkers = nil
	c.muxMu.Unlock()
	for _, w := range workers {
		if w != nil && w.worker != nil {
			_ = w.worker.Close()
		}
	}
}

func (c *Connector) snapshotMuxWorkers() []*vlessMuxWorker {
	c.muxMu.Lock()
	defer c.muxMu.Unlock()

	if len(c.muxWorkers) == 0 {
		return nil
	}
	alive := c.muxWorkers[:0]
	for _, w := range c.muxWorkers {
		if w == nil || w.worker == nil || w.worker.Closed() {
			continue
		}
		alive = append(alive, w)
	}
	c.muxWorkers = alive
	out := make([]*vlessMuxWorker, len(c.muxWorkers))
	copy(out, c.muxWorkers)
	return out
}

func (c *Connector) addMuxWorker(w *vlessMuxWorker) {
	if w == nil || w.worker == nil {
		return
	}
	c.muxMu.Lock()
	c.muxWorkers = append(c.muxWorkers, w)
	c.muxMu.Unlock()
}

func (c *Connector) removeMuxWorker(worker *xmux.ClientWorker) {
	if worker == nil {
		return
	}
	c.muxMu.Lock()
	defer c.muxMu.Unlock()
	if len(c.muxWorkers) == 0 {
		return
	}
	alive := c.muxWorkers[:0]
	for _, w := range c.muxWorkers {
		if w == nil || w.worker == nil || w.worker == worker || w.worker.Closed() {
			continue
		}
		alive = append(alive, w)
	}
	c.muxWorkers = alive
}

func (c *Connector) createMuxWorker(ctx context.Context, conn net.Conn) (*vlessMuxWorker, error) {
	request, requestAddons := c.buildMuxRequest()
	trafficState := proxy.NewTrafficState(c.userID.Bytes())

	bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
	if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("encode mux request header: %w", err)
	}

	clientWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, nil)
	if requestAddons.Flow == xvless.XRV {
		if err := clientWriter.WriteMultiBuffer(make(buf.MultiBuffer, 1)); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("write mux vision padding: %w", err)
		}
	}

	if err := bufferWriter.SetBuffered(false); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("flush mux request: %w", err)
	}

	responseAddons, err := encoding.DecodeResponseHeader(conn, request)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("decode mux response header: %w", err)
	}

	reader := encoding.DecodeBodyAddons(conn, request, responseAddons)
	if requestAddons.Flow == xvless.XRV {
		input, rawInput, err := visionInputBuffers(conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		reader = proxy.NewVisionReader(reader, trafficState, false, ctx, conn, input, rawInput, nil)
	}

	worker, err := xmux.NewClientWorker(transport.Link{
		Reader: reader,
		Writer: clientWriter,
	}, xmux.ClientStrategy{
		MaxConcurrency: uint32(c.muxMax),
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	w := &vlessMuxWorker{worker: worker}
	w.touch()
	go c.watchMuxWorker(w, conn)
	return w, nil
}

func (c *Connector) watchMuxWorker(w *vlessMuxWorker, conn net.Conn) {
	if c.muxIdle <= 0 {
		<-w.worker.WaitClosed()
		_ = conn.Close()
		c.removeMuxWorker(w.worker)
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.worker.WaitClosed():
			_ = conn.Close()
			c.removeMuxWorker(w.worker)
			return
		case <-ticker.C:
			last := time.Unix(0, w.lastUsed.Load())
			if w.worker.ActiveConnections() == 0 && !last.IsZero() && time.Since(last) > c.muxIdle {
				_ = w.worker.Close()
			}
		}
	}
}

func (c *Connector) dispatchMuxStream(ctx context.Context, worker *xmux.ClientWorker, network, address string) (net.Conn, error) {
	target, err := parseDestination(network, address)
	if err != nil {
		return nil, err
	}

	uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))

	link := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}
	dispatchCtx := session.ContextWithOutbounds(ctx, []*session.Outbound{
		{Target: target},
	})

	if !worker.Dispatch(dispatchCtx, link) {
		common.Interrupt(downlinkReader)
		common.Close(downlinkWriter)
		common.Interrupt(uplinkReader)
		common.Close(uplinkWriter)
		return nil, fmt.Errorf("mux worker is full or closed")
	}

	return cnc.NewConnection(
		cnc.ConnectionInputMulti(downlinkWriter),
		cnc.ConnectionOutputMulti(uplinkReader),
		cnc.ConnectionOnClose(&muxStreamCloseHook{
			input:  downlinkWriter,
			output: uplinkReader,
		}),
	), nil
}

func (c *Connector) buildMuxRequest() (*protocol.RequestHeader, *encoding.Addons) {
	flow := c.flow
	if flow == xvless.XRV+"-udp443" {
		flow = xvless.XRV
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

	return &protocol.RequestHeader{
			Version: encoding.Version,
			User:    user,
			Command: protocol.RequestCommandMux,
			Address: xnet.DomainAddress(muxCoolDomain),
			Port:    xnet.Port(muxCoolPort),
		}, &encoding.Addons{
			Flow: flow,
		}
}

func parseDestination(network, address string) (xnet.Destination, error) {
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

func (w *vlessMuxWorker) touch() {
	w.lastUsed.Store(time.Now().UnixNano())
}

type muxStreamCloseHook struct {
	input  *pipe.Writer
	output *pipe.Reader
}

func (h *muxStreamCloseHook) Close() error {
	if h.output != nil {
		common.Interrupt(h.output)
	}
	if h.input != nil {
		return h.input.Close()
	}
	return nil
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
