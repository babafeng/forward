package vless

import (
	"context"
	"fmt"
	"net"

	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"

	"forward/inner/config"
	vhandler "forward/inner/handler/vless"
	"forward/base/logging"
)

const (
	maxConnections   = 2048
	handshakeTimeout = 4 * time.Second
)

type Listener struct {
	addr           string
	listener       internet.Listener
	handler        *vhandler.Handler
	log            *logging.Logger
	streamSettings *internet.MemoryStreamConfig
	xaddr          xnet.Address
	xport          xnet.Port

	url              string
	limit            chan struct{}
	handshakeTimeout time.Duration
}

func NewListener(cfg config.Config, handler *vhandler.Handler, serverCfg *ServerConfig) *Listener {
	return &Listener{
		addr:             serverCfg.Address,
		handler:          handler,
		log:              cfg.Logger,
		streamSettings:   serverCfg.StreamSettings,
		xaddr:            xnet.ParseAddress(serverCfg.Host),
		xport:            xnet.Port(serverCfg.Port),
		url:              serverCfg.URL,
		handshakeTimeout: cfg.HandshakeTimeout,
	}
}

func (l *Listener) Run(ctx context.Context) error {
	l.limit = make(chan struct{}, maxConnections)
	ls, err := internet.ListenTCP(ctx, l.xaddr, l.xport, l.streamSettings, func(conn stat.Connection) {
		go l.handleConn(ctx, conn)
	})
	if err != nil {
		return fmt.Errorf("listen reality failed: %w", err)
	}
	l.listener = ls
	defer ls.Close()

	l.log.Info("VLESS Reality listening on %s", l.addr)

	<-ctx.Done()
	return nil
}

func (l *Listener) handleConn(ctx context.Context, conn net.Conn) {
	select {
	case l.limit <- struct{}{}:
		defer func() { <-l.limit }()
	default:
		conn.Close()
		return
	}

	timeout := l.handshakeTimeout
	if timeout <= 0 {
		timeout = handshakeTimeout
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return
	}

	l.handler.Handle(ctx, conn)
}
