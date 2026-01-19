package reverse

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"

	quic "github.com/quic-go/quic-go"

	"forward/inner/config"
	ctls "forward/inner/config/tls"
	"forward/base/logging"
	rev "forward/inner/reverse"
	"forward/inner/structs"
)

type Handler interface {
	Handle(ctx context.Context, conn net.Conn)
}

type Listener struct {
	addr    string
	handler Handler
	log     *logging.Logger
	tlsCfg  *tls.Config
	scheme  string
}

func New(cfg config.Config, h Handler) (*Listener, error) {
	var tlsCfg *tls.Config
	var err error
	if protos := rev.NextProtosForScheme(cfg.Listen.Scheme); len(protos) > 0 {
		tlsCfg, err = ctls.ServerConfig(cfg, ctls.ServerOptions{
			NextProtos: protos,
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
		scheme:  strings.ToLower(cfg.Listen.Scheme),
	}, nil
}

func (l *Listener) Run(ctx context.Context) error {
	ln, err := l.listen(ctx)
	if err != nil {
		l.log.Error("Reverse server listen error: %v", err)
		return err
	}
	defer ln.Close()

	l.log.Info("Reverse server listening on %s (%s)", l.addr, l.schemeName())

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

func (l *Listener) listen(ctx context.Context) (net.Listener, error) {
	if l.isQuic() {
		qln, err := quic.ListenAddr(l.addr, l.tlsCfg, nil)
		if err != nil {
			return nil, err
		}
		return &quicStreamListener{ctx: ctx, ln: qln}, nil
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", l.addr)
	if err != nil {
		return nil, err
	}
	if l.tlsCfg != nil {
		ln = tls.NewListener(ln, l.tlsCfg)
	}
	return ln, nil
}

func (l *Listener) isQuic() bool {
	return l.scheme == "quic" || l.scheme == "http3"
}

func (l *Listener) schemeName() string {
	if l.isQuic() {
		return "quic"
	}
	if l.tlsCfg != nil {
		return "tls"
	}
	return "tcp"
}

type quicStreamListener struct {
	ctx context.Context
	ln  *quic.Listener
}

func (l *quicStreamListener) Accept() (net.Conn, error) {
	qconn, err := l.ln.Accept(l.ctx)
	if err != nil {
		return nil, err
	}
	stream, err := qconn.AcceptStream(l.ctx)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, err
	}
	go func() {
		for {
			s, err := qconn.AcceptStream(l.ctx)
			if err != nil {
				return
			}
			_ = s.Close()
		}
	}()

	return &structs.QuicStreamConn{
		Stream:    stream,
		Local:     qconn.LocalAddr(),
		Remote:    qconn.RemoteAddr(),
		Closer:    qconn,
		CloseOnce: &sync.Once{},
	}, nil
}

func (l *quicStreamListener) Close() error {
	return l.ln.Close()
}

func (l *quicStreamListener) Addr() net.Addr {
	return l.ln.Addr()
}
