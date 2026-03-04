package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/quic-go/quic-go"

	"forward/base/logging"
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

	ln, err := quic.ListenAddr(l.addr, l.tlsConfig, nil)
	if err != nil {
		return listener.NewBindError(err)
	}
	l.ctx, l.cancel = context.WithCancel(context.Background())
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
	cancel := l.cancel
	l.ln = nil
	l.cancel = nil
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if ln != nil {
		if l.logger != nil {
			l.logger.Info("Listener closed %s", ln.Addr().String())
		}
		return ln.Close()
	}
	return nil
}
