package udp

import (
	"context"
	"errors"
	"net"

	inet "forward/base/io/net"
	"forward/internal/chain"
	corehandler "forward/internal/handler"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/router"
)

func init() {
	registry.HandlerRegistry().Register("udp", NewHandler)
}

type Handler struct {
	options corehandler.Options
	target  string
}

func NewHandler(opts ...corehandler.Option) corehandler.Handler {
	options := corehandler.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	if options.Router == nil {
		options.Router = router.NewStatic(chain.NewRoute())
	}
	return &Handler{options: options}
}

func (h *Handler) Init(md metadata.Metadata) error {
	if md == nil {
		return nil
	}
	h.target = metadata.StringValue(md.Get("target"))
	if h.target == "" {
		h.target = metadata.StringValue(md.Get("forward"))
	}
	if h.target == "" {
		return errors.New("udp handler: missing target")
	}
	return nil
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn, _ ...corehandler.HandleOption) error {
	defer conn.Close()

	if _, ok := conn.(net.PacketConn); !ok {
		return errors.New("udp handler: packet connection required")
	}

	target := h.target
	if target == "" {
		return errors.New("udp handler: missing target")
	}

	remote := conn.RemoteAddr().String()
	local := conn.LocalAddr().String()

	route, err := h.options.Router.Route(ctx, "udp", target)
	if err != nil {
		h.options.Logger.Error("UDP route error: %v", err)
		return err
	}
	if route == nil {
		route = chain.NewRoute()
	}

	up, err := route.Dial(ctx, "udp", target)
	if err != nil {
		h.options.Logger.Error("UDP dial %s error: %v", target, err)
		return err
	}

	bytes, dur, err := inet.Bidirectional(ctx, conn, up)
	if err != nil && ctx.Err() == nil {
		h.options.Logger.Error("UDP transfer error: %v", err)
		if h.options.Logger.IsDebug() {
			h.options.Logger.Debug("UDP closed %s -> %s -> %s transferred %d bytes in %s err=%v", remote, local, target, bytes, dur, err)
		}
		return err
	}
	if h.options.Logger.IsDebug() {
		h.options.Logger.Debug("UDP closed %s -> %s -> %s transferred %d bytes in %s", remote, local, target, bytes, dur)
	}
	return err
}
