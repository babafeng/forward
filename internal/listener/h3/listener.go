package h3

import (
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"

	"forward/base/logging"
	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
)

var errMissingAddr = errors.New("missing listen address")
var errMissingTLS = errors.New("missing tls config")

type listenerMetadata struct {
	backlog          int
	keepAlivePeriod  time.Duration
	handshakeTimeout time.Duration
	maxIdleTimeout   time.Duration
	maxStreams       int
	secret           string
}

type Listener struct {
	addr    net.Addr
	server  *Server
	logger  *logging.Logger
	md      listenerMetadata
	options listener.Options
}

func init() {
	registry.ListenerRegistry().Register("h3", NewListener)
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Listener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *Listener) Init(md metadata.Metadata) error {
	l.parseMetadata(md)

	addr := l.options.Addr
	if addr == "" {
		return listener.NewBindError(errMissingAddr)
	}
	if l.options.TLSConfig == nil {
		return errMissingTLS
	}

	quicCfg := &quic.Config{
		Versions: []quic.Version{
			quic.Version1,
		},
	}
	if l.md.keepAlivePeriod > 0 {
		quicCfg.KeepAlivePeriod = l.md.keepAlivePeriod
	}
	if l.md.handshakeTimeout > 0 {
		quicCfg.HandshakeIdleTimeout = l.md.handshakeTimeout
	}
	if l.md.maxIdleTimeout > 0 {
		quicCfg.MaxIdleTimeout = l.md.maxIdleTimeout
	}
	if l.md.maxStreams > 0 {
		quicCfg.MaxIncomingStreams = int64(l.md.maxStreams)
	}

	opts := []ServerOption{
		TLSConfigServerOption(l.options.TLSConfig),
		BacklogServerOption(l.md.backlog),
		LoggerServerOption(l.logger),
	}
	if l.md.secret != "" {
		opts = append(opts, SecretServerOption(l.md.secret))
	}

	l.server = NewHTTP3Server(
		addr,
		quicCfg,
		opts...,
	)

	go func() {
		if err := l.server.ListenAndServe(); err != nil && l.logger != nil {
			if !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				l.logger.Error("HTTP3 listener error: %v", err)
			}
		}
	}()

	l.addr = l.server.Addr()
	return nil
}

func (l *Listener) Accept() (net.Conn, error) {
	if l.server == nil {
		return nil, listener.ErrClosed
	}
	conn, err := l.server.Accept()
	if err != nil {
		return nil, listener.NewAcceptError(err)
	}
	return conn, nil
}

func (l *Listener) Addr() net.Addr {
	if l.server == nil {
		return l.addr
	}
	if addr := l.server.Addr(); addr != nil {
		return addr
	}
	return l.addr
}

func (l *Listener) Close() error {
	if l.server == nil {
		return nil
	}
	if l.logger != nil && l.Addr() != nil {
		l.logger.Info("Listener closed %s", l.Addr().String())
	}
	return l.server.Close()
}

func (l *Listener) parseMetadata(md metadata.Metadata) {
	parsed := listener.ParsePHTTransportMetadata(md, defaultBacklog)
	l.md.backlog = parsed.Backlog
	l.md.keepAlivePeriod = parsed.KeepAlivePeriod
	l.md.handshakeTimeout = parsed.HandshakeTimeout
	l.md.maxIdleTimeout = parsed.MaxIdleTimeout
	l.md.maxStreams = parsed.MaxStreams
	l.md.secret = parsed.Secret
}
