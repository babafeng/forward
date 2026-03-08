package h2

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"forward/internal/dialer"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.DialerRegistry().Register("h2", NewDialer)
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

		tlsCfg := cloneTLSConfig(d.options.TLSConfig)
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = host
		}
		ensureNextProtos(tlsCfg, []string{"h2"})

		dialTimeout := d.options.Timeout
		tr := &http2.Transport{
			TLSClientConfig:    tlsCfg,
			DisableCompression: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				if cfg == nil {
					cfg = tlsCfg
				} else {
					cfg = cfg.Clone()
				}
				ensureNextProtos(cfg, []string{"h2"})
				dialer := &net.Dialer{Timeout: dialTimeout}
				return (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, network, addr)
			},
		}
		if d.md.keepAlivePeriod > 0 {
			tr.ReadIdleTimeout = d.md.keepAlivePeriod
		}
		if d.md.handshakeTimeout > 0 {
			tr.PingTimeout = d.md.handshakeTimeout
		}
		if d.md.maxIdleTimeout > 0 {
			tr.IdleConnTimeout = d.md.maxIdleTimeout
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
