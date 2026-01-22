package udp

import (
	"context"
	"net"
	"time"

	"forward/internal/config"
	"forward/internal/dialer"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.DialerRegistry().Register("udp", NewDialer)
}

type Dialer struct {
	timeout time.Duration
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	timeout := options.Timeout
	if timeout <= 0 {
		timeout = config.DefaultDialTimeout
	}

	return &Dialer{
		timeout: timeout,
	}
}

func (d *Dialer) Init(md metadata.Metadata) error {
	if md == nil {
		return nil
	}
	if v := md.Get("timeout"); v != nil {
		if t, ok := v.(time.Duration); ok && t > 0 {
			d.timeout = t
		}
	}
	return nil
}

func (d *Dialer) Dial(ctx context.Context, addr string, _ ...dialer.DialOption) (net.Conn, error) {
	nd := &net.Dialer{
		Timeout: d.timeout,
	}
	return nd.DialContext(ctx, "udp", addr)
}
