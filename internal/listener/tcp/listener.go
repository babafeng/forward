package tcp

import (
	"context"
	"errors"
	"net"
	"sync"

	"forward/internal/config"
	"forward/internal/logging"
)

type Handler interface {
	Handle(ctx context.Context, conn net.Conn)
}

type Listener struct {
	addr      string
	handler   Handler
	log       *logging.Logger
	wg        sync.WaitGroup
	proxyDesc string
}

func New(cfg config.Config, h Handler) *Listener {
	proxy := "direct"
	if cfg.Proxy != nil {
		proxy = cfg.Proxy.Address()
	}

	return &Listener{
		addr:      cfg.Listen.Address(),
		handler:   h,
		log:       cfg.Logger,
		proxyDesc: proxy,
	}
}

func (l *Listener) Run(ctx context.Context) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", l.addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	l.log.Info("Forward TCP listening on %s via %s", l.addr, l.proxyDesc)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			l.log.Error("Forward tcp error: accept: %v", err)
			continue
		}

		l.log.Debug("Forward TCP New accept from %s", conn.RemoteAddr().String())

		l.wg.Add(1)
		go func(c net.Conn) {
			defer l.wg.Done()
			l.handler.Handle(ctx, c)
		}(conn)
	}

	l.wg.Wait()
	return nil
}
