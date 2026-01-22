// Package vless 提供 VLESS 协议入站 Handler
package vless

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
	xvless "github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"

	"forward/base/logging"
	"forward/internal/chain"
	"forward/internal/handler"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/router"
)

func init() {
	registry.HandlerRegistry().Register("vless", NewHandler)
}

type Handler struct {
	options   handler.Options
	validator xvless.Validator
}

// NewHandler 创建新的 VLESS Handler
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
	// Validator 需要在外部设置（通过 Listener 配置）
	return nil
}

// SetValidator 设置用户验证器
func (h *Handler) SetValidator(v interface{}) {
	if validator, ok := v.(xvless.Validator); ok {
		h.validator = validator
	}
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	reader, userSentID, request, requestAddons, err := h.readRequest(conn)
	if err != nil {
		h.logf(logging.LevelDebug, "Read VLESS request failed: %v", err)
		return err
	}

	// 清除读取超时
	_ = conn.SetReadDeadline(time.Time{})

	network := "tcp"
	if request.Command == protocol.RequestCommandUDP {
		network = "udp"
	}
	targetAddr := net.JoinHostPort(request.Address.String(), request.Port.String())

	h.logf(logging.LevelInfo, "VLESS connect %s -> %s", conn.RemoteAddr(), targetAddr)

	// 检查 Vision 流
	if requestAddons.Flow == xvless.XRV {
		h.logf(logging.LevelInfo, "VLESS Vision flow detected from %s", conn.RemoteAddr())
		if request.Command == protocol.RequestCommandUDP {
			h.logf(logging.LevelDebug, "VLESS Vision flow rejected for UDP from %s", conn.RemoteAddr())
			return fmt.Errorf("vision flow does not support udp")
		}
	}

	// 获取路由
	route, err := h.options.Router.Route(ctx, network, targetAddr)
	if err != nil {
		h.logf(logging.LevelError, "VLESS route error: %v", err)
		return err
	}
	if route == nil {
		route = chain.NewRoute()
	}

	// 建立上游连接
	targetConn, err := route.Dial(ctx, network, targetAddr)
	if err != nil {
		h.logf(logging.LevelError, "Dial target %s failed: %v", targetAddr, err)
		return err
	}
	defer targetConn.Close()

	// 设置流量状态
	trafficState := proxy.NewTrafficState(userSentID)
	clientReader := encoding.DecodeBodyAddons(reader, request, requestAddons)

	// 处理 Vision 流
	if requestAddons.Flow == xvless.XRV {
		input, rawInput, err := visionInputBuffers(conn)
		if err != nil {
			h.logf(logging.LevelError, "VLESS Vision setup failed: %v", err)
			return err
		}
		clientReader = proxy.NewVisionReader(clientReader, trafficState, true, ctx, conn, input, rawInput, nil)
	}

	// 发送响应头
	bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
	if err := encoding.EncodeResponseHeader(bufferWriter, request, &encoding.Addons{}); err != nil {
		h.logf(logging.LevelDebug, "Write VLESS response failed: %v", err)
		return err
	}
	if err := bufferWriter.SetBuffered(false); err != nil {
		h.logf(logging.LevelDebug, "Flush VLESS response failed: %v", err)
		return err
	}

	clientWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, false, ctx, conn, nil)

	targetReader := buf.NewReader(targetConn)
	targetWriter := buf.NewWriter(targetConn)

	// 双向转发
	if err := bidirectionalCopy(ctx, conn, targetConn, clientReader, clientWriter, targetReader, targetWriter); err != nil && ctx.Err() == nil {
		if requestAddons.Flow == xvless.XRV {
			h.logf(logging.LevelError, "VLESS Vision error: %v", err)
		} else {
			h.logf(logging.LevelError, "VLESS transfer error: %v", err)
		}
		return err
	}

	h.logf(logging.LevelInfo, "VLESS closed %s -> %s", conn.RemoteAddr(), targetAddr)
	return nil
}

func (h *Handler) readRequest(conn net.Conn) (*buf.BufferedReader, []byte, *protocol.RequestHeader, *encoding.Addons, error) {
	if h.validator == nil {
		return nil, nil, nil, nil, fmt.Errorf("vless validator not initialized")
	}

	first := buf.FromBytes(make([]byte, buf.Size))
	first.Clear()
	if _, err := first.ReadFrom(conn); err != nil {
		return nil, nil, nil, nil, err
	}

	reader := &buf.BufferedReader{
		Reader: buf.NewReader(conn),
		Buffer: buf.MultiBuffer{first},
	}

	userSentID, request, requestAddons, _, err := encoding.DecodeRequestHeader(false, first, reader, h.validator)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return reader, userSentID, request, requestAddons, nil
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
func bidirectionalCopy(ctx context.Context, clientConn net.Conn, targetConn net.Conn, clientReader buf.Reader, clientWriter buf.Writer, targetReader buf.Reader, targetWriter buf.Writer) error {
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
		errCh <- buf.Copy(clientReader, targetWriter)
	}()

	// target -> client
	go func() {
		defer wg.Done()
		errCh <- buf.Copy(targetReader, clientWriter)
	}()

	wg.Wait()
	close(stop)

	_ = clientConn.Close()
	_ = targetConn.Close()

	var first error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && first == nil {
			first = err
		}
	}
	return first
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
	case *reality.Conn:
		return xtlsBuffers(c.Conn)
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
		return nil, nil, fmt.Errorf("xtls buffers are nil")
	}

	return input, rawInput, nil
}
