package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"forward/internal/config"
	"forward/internal/dialer"
)

type Dialer struct {
	target   string
	tlsCfg   *tls.Config
	timeout  time.Duration
	baseDial dialer.Dialer
}

func newDialer(cfg config.Config) (dialer.Dialer, error) {
	p := cfg.Proxy
	if p == nil {
		return nil, fmt.Errorf("tls dialer requires proxy")
	}

	base := dialer.NewDirect(cfg)

	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.Insecure, //nolint:gosec
		ServerName:         p.Host,
	}

	return &Dialer{
		target:   p.Address(),
		tlsCfg:   tlsCfg,
		timeout:  10 * time.Second,
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
	if err := client.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = client.SetDeadline(time.Time{})
	return client, nil
}
