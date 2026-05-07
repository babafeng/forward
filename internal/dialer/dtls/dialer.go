package dtls

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/pion/dtls/v2"

	dtlsutil "forward/base/transport/dtls"
	"forward/internal/dialer"
	"forward/internal/dialer/udp"
	"forward/internal/metadata"
	"forward/internal/registry"
)

const defaultBufferSize = 1200

type dialerMetadata struct {
	mtu            int
	bufferSize     int
	flightInterval time.Duration
}

type Dialer struct {
	options dialer.Options
	base    dialer.Dialer
	md      dialerMetadata
}

func init() {
	registry.DialerRegistry().Register("dtls", NewDialer)
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Dialer{
		options: options,
		base:    udp.NewDialer(dialer.TimeoutOption(options.Timeout)),
		md: dialerMetadata{
			bufferSize: defaultBufferSize,
		},
	}
}

func (d *Dialer) Init(md metadata.Metadata) error {
	d.parseMetadata(md)
	return nil
}

func (d *Dialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	return d.base.Dial(ctx, addr, opts...)
}

func (d *Dialer) Handshake(ctx context.Context, conn net.Conn, _ ...dialer.HandshakeOption) (net.Conn, error) {
	tlsCfg := d.options.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{InsecureSkipVerify: true}
	}
	if tlsCfg.ServerName == "" {
		if host := hostFromAddr(conn.RemoteAddr()); host != "" {
			tlsCfg = tlsCfg.Clone()
			tlsCfg.ServerName = host
		}
	}

	cfg := &dtls.Config{
		Certificates:         tlsCfg.Certificates,
		InsecureSkipVerify:   tlsCfg.InsecureSkipVerify,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ServerName:           tlsCfg.ServerName,
		RootCAs:              tlsCfg.RootCAs,
		FlightInterval:       d.md.flightInterval,
		MTU:                  d.md.mtu,
	}

	c, err := dtls.ClientWithContext(ctx, conn, cfg)
	if err != nil {
		return nil, err
	}
	return dtlsutil.Conn(c, d.md.bufferSize), nil
}

func (d *Dialer) parseMetadata(md metadata.Metadata) {
	d.md.bufferSize = defaultBufferSize
	if md == nil {
		return
	}
	if v := metadata.IntValue(md.Get("dtls_mtu")); v > 0 {
		d.md.mtu = v
	}
	if v := metadata.IntValue(md.Get("mtu")); v > 0 {
		d.md.mtu = v
	}
	if v := metadata.IntValue(md.Get("dtls_buffer")); v > 0 {
		d.md.bufferSize = v
	}
	if v := metadata.IntValue(md.Get("buffer_size")); v > 0 {
		d.md.bufferSize = v
	}
	if v := metadata.DurationValue(md.Get("dtls_flight_interval")); v > 0 {
		d.md.flightInterval = v
	}
	if v := metadata.DurationValue(md.Get("flight_interval")); v > 0 {
		d.md.flightInterval = v
	}
}

func hostFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return strings.Trim(addr.String(), "[]")
	}
	return strings.Trim(host, "[]")
}
