package reverse

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	quic "github.com/quic-go/quic-go"

	"forward/internal/config"
	ctls "forward/internal/config/tls"
	"forward/internal/logging"
	"forward/internal/structs"
)

type Handler interface {
	Handle(ctx context.Context, conn net.Conn)
}

type Listener struct {
	addr    string
	handler Handler
	log     *logging.Logger
	tlsCfg  *tls.Config
	isQuic  bool
}

func New(cfg config.Config, h Handler) (*Listener, error) {
	var tlsCfg *tls.Config
	var err error
	switch cfg.Listen.Scheme {
	case "tls", "https":
		tlsCfg, err = ctls.ServerConfig(cfg, ctls.ServerOptions{
			NextProtos: []string{"h2", "http/1.1"},
		})
		if err != nil {
			return nil, err
		}
	case "quic", "http3":
		tlsCfg, err = ctls.ServerConfig(cfg, ctls.ServerOptions{
			NextProtos: []string{"h3"},
		})
		if err != nil {
			return nil, err
		}
	}
	return &Listener{
		addr:    cfg.Listen.Address(),
		handler: h,
		log:     cfg.Logger,
		tlsCfg:  tlsCfg,
		isQuic:  cfg.Listen.Scheme == "quic" || cfg.Listen.Scheme == "http3",
	}, nil
}

func (l *Listener) Run(ctx context.Context) error {
	if l.isQuic {
		return l.runQUIC(ctx)
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", l.addr)
	if err != nil {
		l.log.Error("Reverse server listen error: %v", err)
		return err
	}
	if l.tlsCfg != nil {
		ln = tls.NewListener(ln, l.tlsCfg)
	}
	defer ln.Close()

	l.log.Info("Reverse server listening on %s (%s)", l.addr, schemeName(l.tlsCfg))

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			l.log.Error("Reverse server accept error: %v", err)
			continue
		}
		go l.handler.Handle(ctx, conn)
	}
}

func schemeName(t *tls.Config) string {
	if t != nil {
		return "tls"
	}
	return "tcp"
}

func (l *Listener) runQUIC(ctx context.Context) error {
	qln, err := quic.ListenAddr(l.addr, l.tlsCfg, nil)
	if err != nil {
		l.log.Error("Reverse server quic listen error: %v", err)
		return err
	}
	l.log.Info("Reverse server listening on %s (quic)", l.addr)

	go func() {
		<-ctx.Done()
		qln.Close()
	}()

	for {
		qconn, err := qln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			l.log.Error("Reverse server quic accept error: %v", err)
			continue
		}
		go l.handleQUICConn(ctx, qconn)
	}
}

func (l *Listener) handleQUICConn(ctx context.Context, qconn *quic.Conn) {
	stream, err := qconn.AcceptStream(ctx)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return
	}
	go func() {
		for {
			s, err := qconn.AcceptStream(ctx)
			if err != nil {
				return
			}
			_ = s.Close()
		}
	}()

	conn := &structs.QuicStreamConn{
		Stream:    stream,
		Local:     qconn.LocalAddr(),
		Remote:    qconn.RemoteAddr(),
		Closer:    qconn,
		CloseOnce: &sync.Once{},
	}

	l.handler.Handle(ctx, conn)
}
