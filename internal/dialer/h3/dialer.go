package h3

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"forward/internal/dialer"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.DialerRegistry().Register("h3", NewDialer)
}

type Dialer struct {
	options dialer.Options
	md      dialerMetadata

	mu      sync.Mutex
	clients map[string]*phtClient
}

type dialerMetadata struct {
	authorizePath    string
	pushPath         string
	pullPath         string
	host             string
	keepAlivePeriod  time.Duration
	handshakeTimeout time.Duration
	maxIdleTimeout   time.Duration
	maxStreams       int
	secret           string
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Dialer{
		options: options,
		clients: make(map[string]*phtClient),
	}
}

func (d *Dialer) Init(md metadata.Metadata) error {
	d.parseMetadata(md)
	return nil
}

func (d *Dialer) Dial(ctx context.Context, addr string, _ ...dialer.DialOption) (net.Conn, error) {
	d.mu.Lock()
	client := d.clients[addr]
	if client == nil {
		host := d.md.host
		if host == "" {
			host = hostFromAddr(addr)
		}

		quicCfg := &quic.Config{
			Versions: []quic.Version{
				quic.Version1,
			},
		}
		if d.md.keepAlivePeriod > 0 {
			quicCfg.KeepAlivePeriod = d.md.keepAlivePeriod
		}
		if d.md.handshakeTimeout > 0 {
			quicCfg.HandshakeIdleTimeout = d.md.handshakeTimeout
		}
		if d.md.maxIdleTimeout > 0 {
			quicCfg.MaxIdleTimeout = d.md.maxIdleTimeout
		}
		if d.md.maxStreams > 0 {
			quicCfg.MaxIncomingStreams = int64(d.md.maxStreams)
		}

		tlsCfg := cloneTLSConfig(d.options.TLSConfig)
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

		client = &phtClient{
			Host:          host,
			Client:        &http.Client{Transport: tr},
			AuthorizePath: d.md.authorizePath,
			PushPath:      d.md.pushPath,
			PullPath:      d.md.pullPath,
			TLSEnabled:    true,
			Logger:        d.options.Logger,
			Secret:        d.md.secret,
		}
		d.clients[addr] = client
	}
	d.mu.Unlock()

	// Dial may involve network RTT and should not be serialized under lock.
	return client.Dial(ctx, addr)
}

// Multiplex implements dialer.Multiplexer.
func (d *Dialer) Multiplex() bool {
	return true
}

func (d *Dialer) parseMetadata(md metadata.Metadata) {
	parsed := dialer.ParsePHTTransportMetadata(md)
	d.md.authorizePath = parsed.AuthorizePath
	d.md.pushPath = parsed.PushPath
	d.md.pullPath = parsed.PullPath
	d.md.host = parsed.Host
	d.md.keepAlivePeriod = parsed.KeepAlivePeriod
	d.md.handshakeTimeout = parsed.HandshakeTimeout
	d.md.maxIdleTimeout = parsed.MaxIdleTimeout
	d.md.maxStreams = parsed.MaxStreams
	d.md.secret = parsed.Secret
}

func hostFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.Trim(addr, "[]")
	}
	return strings.Trim(host, "[]")
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}
