// Package vmess 提供 VMess 协议入站 Handler
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
	xvmess "github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/encoding"

	"forward/base/logging"
	pvmess "forward/base/protocol/vmess"
	"forward/internal/chain"
	"forward/internal/handler"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/router"
)

func init() {
	registry.HandlerRegistry().Register("vmess", NewHandler)
}

// Handler VMess 协议入站处理器
type Handler struct {
	options        handler.Options
	validator      *xvmess.TimedUserValidator
	sessionHistory *encoding.SessionHistory
}

// NewHandler 创建新的 VMess Handler
func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	h := &Handler{
		options: options,
	}

	if h.options.Router == nil {
		h.options.Router = router.NewStatic(chain.NewRoute())
	}

	return h
}

func (h *Handler) Init(md metadata.Metadata) error {
	if md == nil {
		return fmt.Errorf("vmess handler requires metadata")
	}

	// 获取 UUID
	uuid := md.GetString(metadata.KeyUUID)
	if uuid == "" {
		return fmt.Errorf("vmess uuid is required")
	}

	// 获取 alterID
	alterID := md.GetInt(metadata.KeyAlterID)

	// 获取加密类型
	security := pvmess.ParseSecurityType(md.GetString(metadata.KeySecurity))

	// 创建用户验证器
	validator, err := pvmess.CreateValidator(pvmess.UserConfig{
		UUID:     uuid,
		AlterID:  alterID,
		Security: security,
	})
	if err != nil {
		return fmt.Errorf("create vmess validator failed: %w", err)
	}

	h.validator = validator
	h.sessionHistory = encoding.NewSessionHistory()
	return nil
}

// SetValidator 设置外部验证器（可选）
func (h *Handler) SetValidator(v interface{}) {
	if validator, ok := v.(*xvmess.TimedUserValidator); ok {
		h.validator = validator
	}
}

// Validator 返回验证器
func (h *Handler) Validator() interface{} {
	return h.validator
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	h.options.Logger.Debug("VMess Handler received connection from %s", conn.RemoteAddr())

	if h.validator == nil {
		return fmt.Errorf("vmess validator not initialized")
	}

	// 创建服务端会话
	session := encoding.NewServerSession(h.validator, h.sessionHistory)

	h.options.Logger.Debug("VMess decoding request header from %s", conn.RemoteAddr())

	// 读取请求头 (isDrain=false 表示不丢弃无效数据)
	request, err := session.DecodeRequestHeader(conn, false)
	if err != nil {
		h.options.Logger.Error("VMess decode request failed from %s: %v", conn.RemoteAddr(), err)
		return err
	}

	// 清除读取超时
	_ = conn.SetReadDeadline(time.Time{})

	network := "tcp"
	if request.Command == protocol.RequestCommandUDP {
		network = "udp"
	}
	targetAddr := net.JoinHostPort(request.Address.String(), request.Port.String())

	h.options.Logger.Info("VMess connect %s -> %s", conn.RemoteAddr(), targetAddr)

	// 获取路由
	route, err := h.options.Router.Route(ctx, network, targetAddr)
	if err != nil {
		h.options.Logger.Error("VMess route error: %v", err)
		return err
	}
	if route == nil {
		route = chain.NewRoute()
	}

	// 建立上游连接
	targetConn, err := route.Dial(ctx, network, targetAddr)
	if err != nil {
		h.options.Logger.Error("Dial target %s failed: %v", targetAddr, err)
		return err
	}
	defer targetConn.Close()

	// 创建请求体读取器
	bodyReader, err := session.DecodeRequestBody(request, conn)
	if err != nil {
		h.options.Logger.Debug("VMess decode request body failed: %v", err)
		return err
	}

	// 创建响应头
	responseHeader := &protocol.ResponseHeader{
		Option: request.Option,
	}

	// 写入响应头 (无返回错误)
	session.EncodeResponseHeader(responseHeader, conn)

	// 创建响应体写入器
	bodyWriter, err := session.EncodeResponseBody(request, conn)
	if err != nil {
		h.options.Logger.Debug("VMess encode response body failed: %v", err)
		return err
	}

	// 双向转发
	if err := bidirectionalCopy(ctx, conn, targetConn, bodyReader, bodyWriter); err != nil && ctx.Err() == nil {
		h.options.Logger.Debug("VMess transfer error: %v", err)
		return err
	}

	h.options.Logger.Info("VMess closed %s -> %s", conn.RemoteAddr(), targetAddr)
	return nil
}

func (h *Handler) logf(level logging.Level, format string, args ...any) {
	if h.options.Logger == nil {
		return
	}
	switch level {
	case logging.LevelDebug:
		h.options.Logger.Debug(format, args...)
	case logging.LevelInfo:
		h.options.Logger.Info(format, args...)
	case logging.LevelWarn:
		h.options.Logger.Warn(format, args...)
	case logging.LevelError:
		h.options.Logger.Error(format, args...)
	}
}

// bidirectionalCopy 双向复制数据
func bidirectionalCopy(ctx context.Context, clientConn net.Conn, targetConn net.Conn, clientReader buf.Reader, clientWriter buf.Writer) error {
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = clientConn.Close()
			_ = targetConn.Close()
		case <-stop:
		}
	}()

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	// client -> target
	go func() {
		defer wg.Done()
		errCh <- buf.Copy(clientReader, buf.NewWriter(targetConn))
	}()

	// target -> client
	go func() {
		defer wg.Done()
		errCh <- buf.Copy(buf.NewReader(targetConn), clientWriter)
	}()

	wg.Wait()
	close(stop)

	_ = clientConn.Close()
	_ = targetConn.Close()

	var first error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && first == nil && err != io.EOF {
			first = err
		}
	}
	return first
}

// Compile-time check
var _ xnet.Address
