// Package ss 提供 Shadowsocks 2022 协议入站 Handler
package ss

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	shadowsocks "github.com/sagernet/sing-shadowsocks"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"forward/base/logging"
	pss "forward/base/protocol/shadowsocks"
	"forward/internal/chain"
	"forward/internal/handler"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/router"
)

func init() {
	registry.HandlerRegistry().Register("ss", NewHandler)
}

// Handler Shadowsocks 2022 协议入站处理器
type Handler struct {
	options handler.Options
	service shadowsocks.Service
	method  string
}

// NewHandler 创建新的 Shadowsocks Handler
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
		return fmt.Errorf("shadowsocks handler requires metadata")
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

	// 创建 Service 实例
	// 使用 300 秒 UDP 超时
	service, err := pss.NewService(method, password, 300, &ssHandler{h: h})
	if err != nil {
		return fmt.Errorf("create shadowsocks service failed: %w", err)
	}

	h.service = service
	h.method = method
	return nil
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	h.options.Logger.Debug("SS Handler received connection from %s", conn.RemoteAddr())

	if h.service == nil {
		return fmt.Errorf("shadowsocks service not initialized")
	}

	// 使用 sing-shadowsocks Service 处理连接
	md := M.Metadata{
		Source: M.SocksaddrFromNet(conn.RemoteAddr()),
	}

	return h.service.NewConnection(ctx, conn, md)
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

// ssHandler 实现 shadowsocks.Handler 接口，处理解密后的连接
type ssHandler struct {
	h *Handler
}

// NewConnection 处理 TCP 连接（在 SS 解密后调用）
func (s *ssHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	targetAddr := metadata.Destination.String()
	network := "tcp"

	s.h.options.Logger.Info("SS connect %s -> %s", metadata.Source, targetAddr)

	// 获取路由
	route, err := s.h.options.Router.Route(ctx, network, targetAddr)
	if err != nil {
		s.h.options.Logger.Error("SS route error: %v", err)
		return err
	}
	if route == nil {
		route = chain.NewRoute()
	}

	// 建立上游连接
	targetConn, err := route.Dial(ctx, network, targetAddr)
	if err != nil {
		s.h.options.Logger.Error("Dial target %s failed: %v", targetAddr, err)
		return err
	}
	defer targetConn.Close()

	// 双向转发
	if err := bidirectionalCopy(ctx, conn, targetConn); err != nil && ctx.Err() == nil {
		s.h.options.Logger.Debug("SS transfer error: %v", err)
		return err
	}

	s.h.options.Logger.Info("SS closed %s -> %s", metadata.Source, targetAddr)
	return nil
}

// NewPacketConnection 处理 UDP 连接
func (s *ssHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	// TODO: 实现 UDP 处理
	s.h.options.Logger.Warn("SS UDP not implemented yet")
	return nil
}

// NewError 处理错误
func (s *ssHandler) NewError(ctx context.Context, err error) {
	s.h.options.Logger.Error("SS error: %v", err)
}

// bidirectionalCopy 双向复制数据
func bidirectionalCopy(ctx context.Context, clientConn net.Conn, targetConn net.Conn) error {
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
		_, err := io.Copy(targetConn, clientConn)
		errCh <- err
		// 半关闭
		if c, ok := targetConn.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()

	// target -> client
	go func() {
		defer wg.Done()
		_, err := io.Copy(clientConn, targetConn)
		errCh <- err
		// 半关闭
		if c, ok := clientConn.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
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

// SetReadDeadline 设置读取超时的辅助函数
func setReadDeadline(conn net.Conn, timeout time.Duration) {
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}
}
