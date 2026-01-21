package quic

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/quic-go/quic-go"

	"forward/internal/dialer"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/structs"
)

func init() {
	registry.DialerRegistry().Register("quic", NewDialer)
}

type Dialer struct {
	options   dialer.Options
	tlsConfig *tls.Config
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	cfg := options.TLSConfig
	if cfg == nil {
		cfg = &tls.Config{}
	}

	return &Dialer{
		options:   options,
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

func (d *Dialer) Dial(ctx context.Context, addr string, _ ...dialer.DialOption) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var cancel context.CancelFunc
	if d.options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, d.options.Timeout)
	}

	tlsCfg := cloneTLSConfig(d.tlsConfig)
	ensureNextProtos(tlsCfg, []string{"h3"})

	qconn, err := quic.DialAddr(ctx, addr, tlsCfg, nil)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, err
	}

	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		_ = qconn.CloseWithError(0, "")
		return nil, err
	}

	return &structs.QuicStreamConn{
		Stream:    stream,
		Local:     qconn.LocalAddr(),
		Remote:    qconn.RemoteAddr(),
		Closer:    qconn,
		CloseOnce: &sync.Once{},
		Cancel:    cancel,
	}, nil
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

func ensureNextProtos(cfg *tls.Config, protos []string) {
	if cfg == nil || len(protos) == 0 {
		return
	}
	existing := map[string]struct{}{}
	for _, p := range cfg.NextProtos {
		existing[p] = struct{}{}
	}
	for _, p := range protos {
		if _, ok := existing[p]; !ok {
			cfg.NextProtos = append(cfg.NextProtos, p)
		}
	}
}
