package vless

import (
	"context"
	"fmt"
	"net"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"

	vhandler "forward/internal/handler/vless"
	"forward/internal/logging"
)

type Listener struct {
	addr           string
	listener       internet.Listener
	handler        *vhandler.Handler
	log            *logging.Logger
	streamSettings *internet.MemoryStreamConfig
	xaddr          xnet.Address
	xport          xnet.Port

	url string
}

func (l *Listener) Run(ctx context.Context) error {
	ls, err := internet.ListenTCP(ctx, l.xaddr, l.xport, l.streamSettings, func(conn stat.Connection) {
		go l.handleConn(ctx, conn)
	})
	if err != nil {
		return fmt.Errorf("listen reality failed: %w", err)
	}
	l.listener = ls
	defer ls.Close()

	l.log.Info("VLESS Reality listening on %s", l.addr)
	if l.url != "" {
		l.log.Info("Shadowrocket URL: %s", l.url)
		l.log.Info("Replace 0.0.0.0 with your real IP in Shadowrocket URL")
	}

	<-ctx.Done()
	return nil
}

func (l *Listener) handleConn(ctx context.Context, conn net.Conn) {
	l.handler.Handle(ctx, conn)
}
