package phtlistener

import (
	"errors"
	"net"
	"net/http"
	"time"

	"forward/base/logging"
	"forward/internal/listener"
	"forward/internal/metadata"
)

var (
	ErrMissingAddr = errors.New("missing listen address")
	ErrMissingTLS  = errors.New("missing tls config")
)

type Metadata struct {
	Backlog          int
	KeepAlivePeriod  time.Duration
	HandshakeTimeout time.Duration
	MaxIdleTimeout   time.Duration
	MaxStreams       int
	Secret           string
}

type Server interface {
	Accept() (net.Conn, error)
	Addr() net.Addr
	Close() error
	ListenAndServe() error
}

type Base struct {
	addr     net.Addr
	server   Server
	Logger   *logging.Logger
	MD       Metadata
	Options  listener.Options
	Protocol string
}

func NewBase(options listener.Options, protocol string) *Base {
	return &Base{
		Logger:   options.Logger,
		Options:  options,
		Protocol: protocol,
	}
}

func (b *Base) InitMetadata(md metadata.Metadata, defaultBacklog int) {
	parsed := listener.ParsePHTTransportMetadata(md, defaultBacklog)
	b.MD.Backlog = parsed.Backlog
	b.MD.KeepAlivePeriod = parsed.KeepAlivePeriod
	b.MD.HandshakeTimeout = parsed.HandshakeTimeout
	b.MD.MaxIdleTimeout = parsed.MaxIdleTimeout
	b.MD.MaxStreams = parsed.MaxStreams
	b.MD.Secret = parsed.Secret
}

func (b *Base) Validate() error {
	if b.Options.Addr == "" {
		return listener.NewBindError(ErrMissingAddr)
	}
	if b.Options.TLSConfig == nil {
		return ErrMissingTLS
	}
	return nil
}

func (b *Base) Start(server Server) {
	b.server = server
	go func() {
		if err := server.ListenAndServe(); err != nil && b.Logger != nil {
			if !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				b.Logger.Error("%s listener error: %v", b.Protocol, err)
			}
		}
	}()
	b.addr = server.Addr()
}

func (b *Base) Accept() (net.Conn, error) {
	if b.server == nil {
		return nil, listener.ErrClosed
	}
	conn, err := b.server.Accept()
	if err != nil {
		return nil, listener.NewAcceptError(err)
	}
	return conn, nil
}

func (b *Base) Addr() net.Addr {
	if b.server == nil {
		return b.addr
	}
	if addr := b.server.Addr(); addr != nil {
		return addr
	}
	return b.addr
}

func (b *Base) Close() error {
	if b.server == nil {
		return nil
	}
	if b.Logger != nil && b.Addr() != nil {
		b.Logger.Info("Listener closed %s", b.Addr().String())
	}
	return b.server.Close()
}
