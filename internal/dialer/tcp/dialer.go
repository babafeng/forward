package tcp

import (
	"context"
	"net"
	"time"

	"forward/internal/config"
	"forward/internal/dialer"
	"forward/internal/metadata"
	"forward/internal/netmark"
	"forward/internal/registry"
)

func init() {
	registry.DialerRegistry().Register("tcp", NewDialer)
	registry.DialerRegistry().Register("direct", NewDialer)
}

type Dialer struct {
	timeout   time.Duration
	keepAlive time.Duration
	resolver  *net.Resolver
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
	keepAlive := config.DefaultDialKeepAlive

	return &Dialer{
		timeout:   timeout,
		keepAlive: keepAlive,
		resolver:  options.Resolver,
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
	if v := md.Get("keepalive"); v != nil {
		if t, ok := v.(time.Duration); ok && t > 0 {
			d.keepAlive = t
		}
	}
	return nil
}

func (d *Dialer) Dial(ctx context.Context, addr string, _ ...dialer.DialOption) (net.Conn, error) {
	nd := &net.Dialer{
		Timeout:   d.timeout,
		KeepAlive: d.keepAlive,
		Resolver:  d.resolver,
	}
	netmark.ConfigureDialer(nd)
	return nd.DialContext(ctx, "tcp", addr)
}
