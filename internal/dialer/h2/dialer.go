package h2

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"golang.org/x/net/http2"

	"forward/internal/dialer"
	"forward/internal/dialer/phtdialer"
	"forward/internal/dialer/transportutil"
	"forward/internal/metadata"
	"forward/internal/netmark"
	"forward/internal/registry"
)

func init() {
	registry.DialerRegistry().Register("h2", NewDialer)
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
		tlsCfg := transportutil.CloneTLSConfig(d.Options.TLSConfig)
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = host
		}
		transportutil.EnsureNextProtos(tlsCfg, []string{"h2"})

		dialTimeout := d.Options.Timeout
		tr := &http2.Transport{
			TLSClientConfig:    tlsCfg,
			DisableCompression: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				if cfg == nil {
					cfg = tlsCfg
				} else {
					cfg = cfg.Clone()
				}
				transportutil.EnsureNextProtos(cfg, []string{"h2"})
				dialer := &net.Dialer{Timeout: dialTimeout}
				netmark.ConfigureDialer(dialer)
				return (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, network, addr)
			},
		}
		if d.MD.KeepAlivePeriod > 0 {
			tr.ReadIdleTimeout = d.MD.KeepAlivePeriod
		}
		if d.MD.HandshakeTimeout > 0 {
			tr.PingTimeout = d.MD.HandshakeTimeout
		}
		if d.MD.MaxIdleTimeout > 0 {
			tr.IdleConnTimeout = d.MD.MaxIdleTimeout
		}
		return tr
	})
}

// Multiplex implements dialer.Multiplexer.
func (d *Dialer) Multiplex() bool {
	return phtdialer.Multiplex()
}
