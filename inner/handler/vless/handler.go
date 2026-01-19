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
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"

	xvless "github.com/xtls/xray-core/proxy/vless"

	"forward/inner/dialer"
	"forward/base/logging"
	"forward/base/route"
)

type Handler struct {
	dialer     dialer.Dialer
	log        *logging.Logger
	validator  xvless.Validator
	routeStore *route.Store
}

func NewHandler(d dialer.Dialer, log *logging.Logger, routeStore *route.Store, validator xvless.Validator) *Handler {
	return &Handler{
		dialer:     d,
		log:        log,
		routeStore: routeStore,
		validator:  validator,
	}
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	reader, userSentID, request, requestAddons, err := h.readRequest(conn)
	if err != nil {
		h.log.Debug("Read VLESS request failed: %v", err)
		return
	}
	conn.SetReadDeadline(time.Time{})

	network := "tcp"
	if request.Command == protocol.RequestCommandUDP {
		network = "udp"
	}
	targetAddr := net.JoinHostPort(request.Address.String(), request.Port.String())

	h.log.Info("VLESS connect %s -> %s", conn.RemoteAddr(), targetAddr)

	if requestAddons.Flow == xvless.XRV {
		h.log.Info("VLESS Vision flow detected from %s", conn.RemoteAddr())
		if request.Command == protocol.RequestCommandUDP {
			h.log.Debug("VLESS Vision flow rejected for UDP from %s", conn.RemoteAddr())
			return
		}
	}

	via, err := route.RouteVia(ctx, h.routeStore, h.log, conn.RemoteAddr().String(), targetAddr)
	if err != nil {
		h.log.Error("VLESS route error: %v", err)
		return
	}
	if route.IsReject(via) {
		return
	}

	targetConn, err := dialer.DialContextVia(ctx, h.dialer, network, targetAddr, via)
	if err != nil {
		h.log.Error("Dial target %s failed: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	trafficState := proxy.NewTrafficState(userSentID)
	clientReader := encoding.DecodeBodyAddons(reader, request, requestAddons)

	if requestAddons.Flow == xvless.XRV {
		input, rawInput, err := visionInputBuffers(conn)
		if err != nil {
			h.log.Error("VLESS Vision setup failed: %v", err)
			return
		}
		clientReader = proxy.NewVisionReader(clientReader, trafficState, true, ctx, conn, input, rawInput, nil)
	}

	bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
	if err := encoding.EncodeResponseHeader(bufferWriter, request, &encoding.Addons{}); err != nil {
		h.log.Debug("Write VLESS response failed: %v", err)
		return
	}
	if err := bufferWriter.SetBuffered(false); err != nil {
		h.log.Debug("Flush VLESS response failed: %v", err)
		return
	}
	clientWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, false, ctx, conn, nil)

	targetReader := buf.NewReader(targetConn)
	targetWriter := buf.NewWriter(targetConn)

	if err := bidirectionalCopy(ctx, conn, targetConn, clientReader, clientWriter, targetReader, targetWriter); err != nil && ctx.Err() == nil {
		if requestAddons.Flow == xvless.XRV {
			h.log.Error("VLESS Vision error: %v", err)
		} else {
			h.log.Error("VLESS transfer error: %v", err)
		}
		return
	}
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

	p := unsafe.Pointer(val.Pointer())
	input := (*bytes.Reader)(unsafe.Pointer(uintptr(p) + inputField.Offset))
	rawInput := (*bytes.Buffer)(unsafe.Pointer(uintptr(p) + rawInputField.Offset))

	if input == nil || rawInput == nil {
		return nil, nil, fmt.Errorf("xtls buffers are nil")
	}

	return input, rawInput, nil
}

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

	go func() {
		defer wg.Done()
		errCh <- buf.Copy(clientReader, targetWriter)
	}()
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
