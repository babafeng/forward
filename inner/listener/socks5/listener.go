package socks5

import (
	"context"
	"net"

	"forward/inner/config"
	ltcp "forward/inner/listener/tcp"
)

type Handler interface {
	Handle(ctx context.Context, conn net.Conn)
}

type Listener struct {
	inner *ltcp.Listener
}

func New(cfg config.Config, h Handler) *Listener {
	return &Listener{
		inner: ltcp.New(cfg, h),
	}
}

func (l *Listener) Run(ctx context.Context) error {
	return l.inner.Run(ctx)
}
