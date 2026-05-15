package h3

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"forward/internal/config"
	"forward/internal/dialer"
	"forward/internal/dialer/phtdialer"
	"forward/internal/dialer/transportutil"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.DialerRegistry().Register("h3", NewDialer)
}

type Dialer struct {
	phtdialer.Base
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Dialer{Base: phtdialer.NewBase(options)}
}

func (d *Dialer) Init(md metadata.Metadata) error {
	d.Base.Init(md)
	return nil
}

func (d *Dialer) Dial(ctx context.Context, addr string, _ ...dialer.DialOption) (net.Conn, error) {
	return d.Base.Dial(ctx, addr, func(host string) http.RoundTripper {
		quicCfg := config.NewClientQUICConfig()
		if d.MD.KeepAlivePeriod > 0 {
			quicCfg.KeepAlivePeriod = d.MD.KeepAlivePeriod
		}
		if d.MD.HandshakeTimeout > 0 {
			quicCfg.HandshakeIdleTimeout = d.MD.HandshakeTimeout
		}
		if d.MD.MaxIdleTimeout > 0 {
			quicCfg.MaxIdleTimeout = d.MD.MaxIdleTimeout
		}
		if d.MD.MaxStreams > 0 {
			quicCfg.MaxIncomingStreams = int64(d.MD.MaxStreams)
		}

		tlsCfg := transportutil.CloneTLSConfig(d.Options.TLSConfig)
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = host
		}

		tr := &http3.Transport{
			TLSClientConfig:    tlsCfg,
			QUICConfig:         quicCfg,
			DisableCompression: true,
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
			},
		}
		return tr
	})
}

// Multiplex implements dialer.Multiplexer.
func (d *Dialer) Multiplex() bool {
	return phtdialer.Multiplex()
}
