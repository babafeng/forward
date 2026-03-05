// Package vmess 提供 VMess 协议 Connector（出站）
package vmess

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xmux "github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vmess/encoding"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	pvmess "forward/base/protocol/vmess"
	"forward/internal/connector"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.ConnectorRegistry().Register("vmess", NewConnector)
}

const (
	defaultMuxMaxStreams = 16
	defaultMuxIdle       = 120 * time.Second
	muxCoolDomain        = "v1.mux.cool"
	muxCoolPort          = 9527
)

// Connector VMess 协议 Connector
type Connector struct {
	user     *protocol.MemoryUser
	security protocol.SecurityType
	mux      bool
	muxMax   int
	muxIdle  time.Duration
	options  connector.Options

	muxMu       sync.Mutex
	muxWorkers  []*vmessMuxWorker
	muxDisabled atomic.Bool
}

type vmessMuxWorker struct {
	worker   *xmux.ClientWorker
	lastUsed atomic.Int64
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
		c.options.Logger.Info("VMess mux enabled: max_streams=%d idle=%s", c.muxMax, c.muxIdle)
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
		return nil, true, fmt.Errorf("vmess mux bootstrap failed: %w", err)
	}
	c.addMuxWorker(w)

	streamConn, err := c.dispatchMuxStream(ctx, w.worker, network, address)
	if err != nil {
		_ = w.worker.Close()
		c.removeMuxWorker(w.worker)
		return nil, true, fmt.Errorf("vmess mux dispatch failed: %w", err)
	}
	w.touch()
	return streamConn, true, nil
}

func (c *Connector) disableMux(reason error) {
	if !c.muxDisabled.CompareAndSwap(false, true) {
		return
	}
	if c.options.Logger != nil {
		c.options.Logger.Warn("VMess mux disabled, fallback to direct forwarding: %v", reason)
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

func (c *Connector) snapshotMuxWorkers() []*vmessMuxWorker {
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
	out := make([]*vmessMuxWorker, len(c.muxWorkers))
	copy(out, c.muxWorkers)
	return out
}

func (c *Connector) addMuxWorker(w *vmessMuxWorker) {
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

func (c *Connector) createMuxWorker(ctx context.Context, conn net.Conn) (*vmessMuxWorker, error) {
	if c.user == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("vmess user not initialized")
	}

	request := &protocol.RequestHeader{
		Version:  encoding.Version,
		User:     c.user,
		Command:  protocol.RequestCommandMux,
		Address:  xnet.DomainAddress(muxCoolDomain),
		Port:     xnet.Port(muxCoolPort),
		Security: c.security,
		Option:   protocol.RequestOptionChunkStream | protocol.RequestOptionChunkMasking,
	}

	clientSession := encoding.NewClientSession(ctx, time.Now().UnixNano())
	if err := clientSession.EncodeRequestHeader(request, conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("encode mux request header: %w", err)
	}

	bodyWriter, err := clientSession.EncodeRequestBody(request, conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("encode mux request body: %w", err)
	}

	if _, err := clientSession.DecodeResponseHeader(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("decode mux response header: %w", err)
	}
	bodyReader, err := clientSession.DecodeResponseBody(request, conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("decode mux response body: %w", err)
	}

	worker, err := xmux.NewClientWorker(transport.Link{
		Reader: bodyReader,
		Writer: bodyWriter,
	}, xmux.ClientStrategy{
		MaxConcurrency: uint32(c.muxMax),
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	w := &vmessMuxWorker{worker: worker}
	w.touch()
	go c.watchMuxWorker(w, conn)
	return w, nil
}

func (c *Connector) watchMuxWorker(w *vmessMuxWorker, conn net.Conn) {
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

func parseDestination(network, address string) (xnet.Destination, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("invalid target address %q: %w", address, err)
	}
	port, err := xnet.PortFromString(portStr)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("invalid target port %q: %w", portStr, err)
	}
	if network == "udp" || network == "udp4" || network == "udp6" {
		return xnet.UDPDestination(xnet.ParseAddress(host), port), nil
	}
	return xnet.TCPDestination(xnet.ParseAddress(host), port), nil
}

func (w *vmessMuxWorker) touch() {
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

// vmessConn 封装 VMess 连接
type vmessConn struct {
	net.Conn
	session    *encoding.ClientSession
	request    *protocol.RequestHeader
	bodyWriter buf.Writer
	reader     *buf.BufferedReader

	initOnce sync.Once
	initErr  error
}

func (c *vmessConn) Read(p []byte) (int, error) {
	if err := c.initReader(); err != nil {
		return 0, err
	}
	return c.reader.Read(p)
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
		c.reader = &buf.BufferedReader{Reader: bodyReader}
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
