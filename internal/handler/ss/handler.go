// Package ss 提供 Shadowsocks 2022 协议入站 Handler
package ss

import (
	"context"
	"fmt"
	"net"
	"time"

	shadowsocks "github.com/sagernet/sing-shadowsocks"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	inet "forward/base/io/net"
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

// ssHandler 实现 shadowsocks.Handler 接口，处理解密后的连接
type ssHandler struct {
	h *Handler
}

// NewConnection 处理 TCP 连接（在 SS 解密后调用）
func (s *ssHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	targetAddr := metadata.Destination.String()
	network := "tcp"

	s.h.options.Logger.Debug("SS connect %s -> %s", metadata.Source, targetAddr)

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

	s.h.options.Logger.Debug("SS closed %s -> %s", metadata.Source, targetAddr)
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
	_, _, err := inet.Bidirectional(ctx, clientConn, targetConn)
	return err
}

// SetReadDeadline 设置读取超时的辅助函数
func setReadDeadline(conn net.Conn, timeout time.Duration) {
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}
}
