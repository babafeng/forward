package tls

import (
	"context"
	"crypto/tls"
	"net"

	"forward/internal/dialer"
	"forward/internal/metadata"
	"forward/internal/registry"
	tcpdialer "forward/internal/dialer/tcp"
)

func init() {
	registry.DialerRegistry().Register("tls", NewDialer)
}

type Dialer struct {
	base      dialer.Dialer
	tlsConfig *tls.Config
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	base := tcpdialer.NewDialer(dialer.TimeoutOption(options.Timeout))
	cfg := options.TLSConfig
	if cfg == nil {
		cfg = &tls.Config{}
	}
	return &Dialer{
		base:      base,
		tlsConfig: cfg,
	}
}

func (d *Dialer) Init(md metadata.Metadata) error {
	if md == nil {
		return nil
	}
	if v := md.Get("tls_config"); v != nil {
		if cfg, ok := v.(*tls.Config); ok && cfg != nil {
			d.tlsConfig = cfg
		}
	}
	return nil
}

func (d *Dialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	return d.base.Dial(ctx, addr, opts...)
}

func (d *Dialer) Handshake(ctx context.Context, conn net.Conn, _ ...dialer.HandshakeOption) (net.Conn, error) {
	cfg := d.tlsConfig
	if cfg == nil {
		cfg = &tls.Config{}
	}
	tlsConn := tls.Client(conn, cfg.Clone())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tlsConn, nil
}
