package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/quic-go/quic-go"

	"forward/base/logging"
	"forward/internal/config"
	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/structs"
)

var errMissingAddr = errors.New("missing listen address")
var errMissingTLS = errors.New("missing tls config")

type Listener struct {
	addr      string
	tlsConfig *tls.Config
	logger    *logging.Logger

	pc     net.PacketConn
	ln     *quic.Listener
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
}

func init() {
	registry.ListenerRegistry().Register("quic", NewListener)
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Listener{
		addr:      options.Addr,
		tlsConfig: options.TLSConfig,
		logger:    options.Logger,
	}
}

func (l *Listener) Init(_ metadata.Metadata) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln != nil {
		return nil
	}
	if l.addr == "" {
		return listener.NewBindError(errMissingAddr)
	}
	if l.tlsConfig == nil {
		return errMissingTLS
	}

	pc, err := net.ListenPacket("udp", l.addr)
	if err != nil {
		return listener.NewBindError(err)
	}
	// 不在此处调 netmark.TuneUDPConn：quic-go 会在 wrapConn 里把 UDP
	// 接收缓冲区尝试拉到 7MB，netmark 的 4MB 基线会先把 pc 设到 4MB，
	// 在 rmem_max < 7MB 的系统上 quic-go 的 setReadBuffer 会被 cap 在
	// 4MB 并触发 "UDP-Buffer-Sizes" 警告。让 quic-go 自己 tune 更干净。

	ln, err := quic.Listen(pc, l.tlsConfig, config.NewServerQUICConfig())
	if err != nil {
		_ = pc.Close()
		return listener.NewBindError(err)
	}
	l.ctx, l.cancel = context.WithCancel(context.Background())
	l.pc = pc
	l.ln = ln
	return nil
}

func (l *Listener) Accept() (net.Conn, error) {
	l.mu.Lock()
	ln := l.ln
	ctx := l.ctx
	l.mu.Unlock()
	if ln == nil {
		return nil, listener.ErrClosed
	}

	qconn, err := ln.Accept(ctx)
	if err != nil {
		return nil, listener.NewAcceptError(err)
	}

	stream, err := qconn.AcceptStream(ctx)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, listener.NewAcceptError(err)
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

	return &structs.QuicStreamConn{
		Stream:    stream,
		Local:     qconn.LocalAddr(),
		Remote:    qconn.RemoteAddr(),
		Closer:    qconn,
		CloseOnce: &sync.Once{},
	}, nil
}

func (l *Listener) Addr() net.Addr {
	l.mu.Lock()
	ln := l.ln
	l.mu.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Addr()
}

func (l *Listener) Close() error {
	l.mu.Lock()
	ln := l.ln
	pc := l.pc
	cancel := l.cancel
	l.ln = nil
	l.pc = nil
	l.cancel = nil
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var err error
	if ln != nil {
		if l.logger != nil {
			l.logger.Info("Listener closed %s", ln.Addr().String())
		}
		err = ln.Close()
	}
	if pc != nil {
		if cerr := pc.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}
