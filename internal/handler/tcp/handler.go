package tcp

import (
	"context"
	"errors"
	"net"
	"strings"

	inet "forward/base/io/net"
	"forward/base/logging"
	"forward/internal/chain"
	corehandler "forward/internal/handler"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/router"
)

func init() {
	registry.HandlerRegistry().Register("tcp", NewHandler)
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
	h.target = getString(md.Get("target"))
	if h.target == "" {
		h.target = getString(md.Get("forward"))
	}
	if h.target == "" {
		return errors.New("tcp handler: missing target")
	}
	return nil
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn, _ ...corehandler.HandleOption) error {
	defer conn.Close()

	target := h.target
	if target == "" {
		return errors.New("tcp handler: missing target")
	}

	remote := conn.RemoteAddr().String()
	local := conn.LocalAddr().String()
	h.logf(logging.LevelInfo, "TCP connection %s -> %s", remote, local)

	route, err := h.options.Router.Route(ctx, "tcp", target)
	if err != nil {
		h.logf(logging.LevelError, "TCP route error: %v", err)
		return err
	}
	if route == nil {
		route = chain.NewRoute()
	}
	h.logf(logging.LevelDebug, "TCP route via %s", chain.RouteSummary(route))

	up, err := route.Dial(ctx, "tcp", target)
	if err != nil {
		h.logf(logging.LevelError, "TCP dial %s error: %v", target, err)
		return err
	}

	bytes, dur, err := inet.Bidirectional(ctx, conn, up)
	if err != nil && ctx.Err() == nil {
		h.logf(logging.LevelError, "TCP transfer error: %v", err)
	}
	h.logf(logging.LevelDebug, "TCP closed %s -> %s transferred %d bytes in %s", remote, target, bytes, dur)
	return err
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

func getString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return ""
	}
}
