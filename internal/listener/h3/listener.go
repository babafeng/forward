package h3

import (
	"forward/internal/config"
	"forward/internal/listener"
	"forward/internal/listener/phtlistener"
	"forward/internal/metadata"
	"forward/internal/registry"
)

type Listener struct {
	*phtlistener.Base
}

func init() {
	registry.ListenerRegistry().Register("h3", NewListener)
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Listener{Base: phtlistener.NewBase(options, "HTTP3")}
}

func (l *Listener) Init(md metadata.Metadata) error {
	l.InitMetadata(md, defaultBacklog)
	if err := l.Validate(); err != nil {
		return err
	}

	quicCfg := config.NewServerQUICConfig()
	if l.MD.KeepAlivePeriod > 0 {
		quicCfg.KeepAlivePeriod = l.MD.KeepAlivePeriod
	}
	if l.MD.HandshakeTimeout > 0 {
		quicCfg.HandshakeIdleTimeout = l.MD.HandshakeTimeout
	}
	if l.MD.MaxIdleTimeout > 0 {
		quicCfg.MaxIdleTimeout = l.MD.MaxIdleTimeout
	}
	if l.MD.MaxStreams > 0 {
		quicCfg.MaxIncomingStreams = int64(l.MD.MaxStreams)
	}

	opts := []ServerOption{
		TLSConfigServerOption(l.Options.TLSConfig),
		BacklogServerOption(l.MD.Backlog),
		LoggerServerOption(l.Logger),
	}
	if l.MD.Secret != "" {
		opts = append(opts, SecretServerOption(l.MD.Secret))
	}

	l.Start(NewHTTP3Server(
		l.Options.Addr,
		quicCfg,
		opts...,
	))
	return nil
}
