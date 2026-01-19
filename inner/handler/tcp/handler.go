package tcp

import (
	"context"
	"net"

	"forward/inner/config"
	"forward/inner/dialer"
	inet "forward/inner/io/net"
	"forward/inner/logging"
)

type Handler struct {
	target string
	dialer dialer.Dialer
	log    *logging.Logger
}

func New(cfg config.Config, d dialer.Dialer) *Handler {
	return &Handler{
		target: cfg.Forward.Address(),
		dialer: d,
		log:    cfg.Logger,
	}
}

func (h *Handler) Handle(ctx context.Context, in net.Conn) {
	defer in.Close()

	src := in.RemoteAddr().String()
	dst := h.target

	h.log.Info("Forward TCP Received connection %s --> %s", src, dst)
	out, err := h.dialer.DialContext(ctx, "tcp", dst)
	if err != nil {
		h.log.Error("Forward tcp error: dial %s: %v", dst, err)
		return
	}
	defer out.Close()

	h.log.Debug("Forward TCP Connected to upstream %s --> %s", src, dst)

	bytes, dur, err := inet.Bidirectional(ctx, in, out)
	if err != nil && ctx.Err() == nil {
		h.log.Error("Forward tcp error: transfer: %v", err)
	}

	h.log.Debug("Forward TCP Closed connection %s --> %s transferred %d bytes in %s", src, dst, bytes, dur)
}
