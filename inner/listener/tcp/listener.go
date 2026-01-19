package tcp

import (
	"context"
	"errors"
	"net"
	"sync"

	"forward/inner/config"
	"forward/base/logging"
)

type Handler interface {
	Handle(ctx context.Context, conn net.Conn)
}

type Listener struct {
	addr        string
	handler     Handler
	log         *logging.Logger
	wg          sync.WaitGroup
	forwardDesc string
	sem         chan struct{}
}

func New(cfg config.Config, h Handler) *Listener {
	forward := "direct"
	if cfg.Forward != nil && cfg.Mode != config.ModePortForward {
		forward = cfg.Forward.Address()
	}

	return &Listener{
		addr:        cfg.Listen.Address(),
		handler:     h,
		log:         cfg.Logger,
		forwardDesc: forward,
		sem:         make(chan struct{}, config.DefaultMaxConnections),
	}
}

func (l *Listener) Run(ctx context.Context) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", l.addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	l.log.Info("Forward TCP listening on %s via %s", l.addr, l.forwardDesc)

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
			l.log.Error("Forward TCP error: accept: %v", err)
			continue
		}

		l.log.Debug("Forward TCP New accept from %s", conn.RemoteAddr().String())

		l.sem <- struct{}{}
		l.wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				<-l.sem
				l.wg.Done()
			}()
			l.handler.Handle(ctx, c)
		}(conn)
	}

	l.wg.Wait()
	return nil
}
