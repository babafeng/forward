package udp

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"forward/internal/config"
	"forward/internal/logging"
	"forward/internal/pool"
)

type Handler interface {
	Handle(ctx context.Context, conn *net.UDPConn, pkt []byte, src *net.UDPAddr)
}

type Listener struct {
	addr    string
	handler Handler
	log     *logging.Logger
	wg      sync.WaitGroup
}

func New(cfg config.Config, h Handler) *Listener {
	return &Listener{
		addr:    cfg.Listen.Address(),
		handler: h,
		log:     cfg.Logger,
	}
}

func (l *Listener) Run(ctx context.Context) error {
	laddr, err := net.ResolveUDPAddr("udp", l.addr)
	if err != nil {
		l.log.Error("Forward udp error: resolve listen addr: %v", err)
		return err
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		l.log.Error("Forward udp error: listen: %v", err)
		return err
	}
	defer conn.Close()

	l.log.Info("Forward UDP listening on %s", l.addr)

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	for {
		pkt := pool.Get()
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(pkt)

		if err != nil {
			pool.Put(pkt)
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			l.log.Error("Forward udp error: read: %v", err)
			continue
		}
		if n == 0 {
			pool.Put(pkt)
			continue
		}

		l.wg.Add(1)
		go func(pkt []byte, src *net.UDPAddr) {
			defer l.wg.Done()
			l.handler.Handle(ctx, conn, pkt, src)
		}(pkt[:n], src)
	}

	l.wg.Wait()
	return nil
}
