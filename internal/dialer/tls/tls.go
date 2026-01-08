package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"forward/internal/config"
	ctls "forward/internal/config/tls"
	"forward/internal/dialer"
)

type Dialer struct {
	target   string
	tlsCfg   *tls.Config
	timeout  time.Duration
	baseDial dialer.Dialer
}

func New(cfg config.Config) (dialer.Dialer, error) {
	forward := cfg.Forward

	base := dialer.NewDirect(cfg)

	tlsCfg, err := ctls.ClientConfig(*forward, cfg.Insecure, ctls.ClientOptions{
		ServerName: forward.Host,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil, err
	}

	return &Dialer{
		target:   forward.Address(),
		tlsCfg:   tlsCfg,
		timeout:  cfg.DialTimeout,
		baseDial: base,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("tls dialer supports tcp only")
	}
	conn, err := d.baseDial.DialContext(ctx, "tcp", d.target)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	client := tls.Client(conn, d.tlsCfg)
	if err := client.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = client.SetDeadline(time.Time{})
	return client, nil
}
