package h2

import (
	"forward/internal/dialer/transportutil"
	"forward/internal/listener"
	"forward/internal/listener/phtlistener"
	"forward/internal/metadata"
	"forward/internal/registry"
)

type Listener struct {
	*phtlistener.Base
}

func init() {
	registry.ListenerRegistry().Register("h2", NewListener)
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Listener{Base: phtlistener.NewBase(options, "HTTP2")}
}

func (l *Listener) Init(md metadata.Metadata) error {
	l.InitMetadata(md, defaultBacklog)
	if err := l.Validate(); err != nil {
		return err
	}

	tlsCfg := transportutil.CloneTLSConfig(l.Options.TLSConfig)
	transportutil.EnsureNextProtos(tlsCfg, []string{"h2"})

	opts := []ServerOption{
		TLSConfigServerOption(tlsCfg),
		BacklogServerOption(l.MD.Backlog),
		LoggerServerOption(l.Logger),
	}
	if l.MD.KeepAlivePeriod > 0 {
		opts = append(opts, ReadIdleTimeoutServerOption(l.MD.KeepAlivePeriod))
	}
	if l.MD.HandshakeTimeout > 0 {
		opts = append(opts, ReadHeaderTimeoutServerOption(l.MD.HandshakeTimeout))
	}
	if l.MD.MaxIdleTimeout > 0 {
		opts = append(opts, IdleTimeoutServerOption(l.MD.MaxIdleTimeout))
	}
	if l.MD.MaxStreams > 0 {
		opts = append(opts, MaxStreamsServerOption(uint32(l.MD.MaxStreams)))
	}
	if l.MD.Secret != "" {
		opts = append(opts, SecretServerOption(l.MD.Secret))
	}

	l.Start(NewServer(l.Options.Addr, opts...))
	return nil
}
