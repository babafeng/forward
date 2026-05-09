// Package trojan provides Trojan protocol inbound Handler support.
package trojan

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	xtrojan "github.com/xtls/xray-core/proxy/trojan"
	xudp "github.com/xtls/xray-core/transport/internet/udp"

	ptrojan "forward/base/protocol/trojan"
	"forward/internal/chain"
	"forward/internal/handler"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/router"
	"forward/internal/xraymux"
)

func init() {
	registry.HandlerRegistry().Register("trojan", NewHandler)
}

type Handler struct {
	options   handler.Options
	validator *xtrojan.Validator
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	h := &Handler{options: options}
	if h.options.Router == nil {
		h.options.Router = router.NewStatic(chain.NewRoute())
	}
	return h
}

func (h *Handler) Init(md metadata.Metadata) error {
	password := ""
	if md != nil {
		password = strings.TrimSpace(md.GetString(metadata.KeyPassword))
	}
	if password == "" && h.options.Auth != nil {
		password = strings.TrimSpace(h.options.Auth.Username())
		if p, ok := h.options.Auth.Password(); ok && strings.TrimSpace(p) != "" {
			password = strings.TrimSpace(p)
		}
	}
	if password == "" {
		return fmt.Errorf("trojan password is required")
	}
	validator, err := ptrojan.CreateValidator(password)
	if err != nil {
		return fmt.Errorf("create trojan validator failed: %w", err)
	}
	h.validator = validator
	return nil
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()
	if h.validator == nil {
		return fmt.Errorf("trojan validator not initialized")
	}

	first := buf.FromBytes(make([]byte, buf.Size))
	first.Clear()
	if _, err := first.ReadFrom(conn); err != nil {
		return err
	}
	if first.Len() < 58 || first.Byte(56) != '\r' {
		first.Release()
		return fmt.Errorf("invalid trojan request")
	}
	if h.validator.Get(hexString(first.BytesTo(56))) == nil {
		first.Release()
		return fmt.Errorf("invalid trojan user")
	}

	reader := &buf.BufferedReader{
		Reader: buf.NewReader(conn),
		Buffer: buf.MultiBuffer{first},
	}
	clientReader := &xtrojan.ConnReader{Reader: reader}
	if err := clientReader.ParseHeader(); err != nil {
		return fmt.Errorf("trojan request decode failed: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	destination := clientReader.Target
	network, targetAddr := destinationToTarget(destination)
	if destination.Network == xnet.Network_UDP {
		return h.handleUDP(ctx, &xtrojan.PacketReader{Reader: clientReader}, &xtrojan.PacketWriter{Writer: conn})
	}

	rt, err := h.options.Router.Route(ctx, network, targetAddr)
	if err != nil {
		return fmt.Errorf("trojan route error: %w", err)
	}
	if rt == nil {
		rt = chain.NewRoute()
	}
	targetConn, err := rt.Dial(ctx, network, targetAddr)
	if err != nil {
		return fmt.Errorf("dial target %s failed: %w", targetAddr, err)
	}
	defer targetConn.Close()

	if err := xraymux.Bidirectional(ctx, conn, targetConn, clientReader, buf.NewWriter(conn), buf.NewReader(targetConn), buf.NewWriter(targetConn)); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func (h *Handler) handleUDP(ctx context.Context, clientReader *xtrojan.PacketReader, clientWriter *xtrojan.PacketWriter) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	dispatcher := xraymux.NewRouteDispatcher(h.options.Router, h.options.Logger)
	udpServer := xudp.NewDispatcher(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
		payload := packet.Payload
		if payload.UDP == nil {
			payload.UDP = &packet.Source
		}
		if err := clientWriter.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
			cancel()
		}
	})
	defer udpServer.RemoveRay()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		mb, err := clientReader.ReadMultiBuffer()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		mb2, b := buf.SplitFirst(mb)
		if b == nil {
			continue
		}
		destination := *b.UDP
		udpServer.Dispatch(ctx, destination, b)
		for _, payload := range mb2 {
			udpServer.Dispatch(ctx, destination, payload)
		}
	}
}

func destinationToTarget(dest xnet.Destination) (string, string) {
	network := "tcp"
	if dest.Network == xnet.Network_UDP {
		network = "udp"
	}
	return network, net.JoinHostPort(dest.Address.String(), dest.Port.String())
}

func hexString(data []byte) string {
	str := ""
	for _, v := range data {
		str += fmt.Sprintf("%02x", v)
	}
	return str
}
