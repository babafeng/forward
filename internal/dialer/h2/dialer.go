package h2

import (
	"context"
	"crypto/tls"
	"fmt"
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
	defer d.mu.Unlock()

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

	return client.Dial(ctx, addr)
}

// Multiplex implements dialer.Multiplexer.
func (d *Dialer) Multiplex() bool {
	return true
}

func (d *Dialer) parseMetadata(md metadata.Metadata) {
	d.md.authorizePath = "/authorize"
	d.md.pushPath = "/push"
	d.md.pullPath = "/pull"
	if md == nil {
		return
	}

	if v := getString(md.Get("authorize_path")); v != "" {
		d.md.authorizePath = ensurePath(v, d.md.authorizePath)
	}
	if v := getString(md.Get("push_path")); v != "" {
		d.md.pushPath = ensurePath(v, d.md.pushPath)
	}
	if v := getString(md.Get("pull_path")); v != "" {
		d.md.pullPath = ensurePath(v, d.md.pullPath)
	}
	if v := getString(md.Get("host")); v != "" {
		d.md.host = v
	}

	if getBool(md.Get("keepalive")) {
		if v := getDuration(md.Get("ttl")); v > 0 {
			d.md.keepAlivePeriod = v
		}
		if v := getDuration(md.Get("keepalive_period")); v > 0 {
			d.md.keepAlivePeriod = v
		}
	}
	if v := getDuration(md.Get("handshake_timeout")); v > 0 {
		d.md.handshakeTimeout = v
	}
	if v := getDuration(md.Get("max_idle_timeout")); v > 0 {
		d.md.maxIdleTimeout = v
	}
	if v := getString(md.Get("secret")); v != "" {
		d.md.secret = v
	}
}

func ensurePath(v, fallback string) string {
	if v == "" {
		return fallback
	}
	if !strings.HasPrefix(v, "/") {
		return fallback
	}
	return v
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

func getString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return ""
	}
}

func getBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		t = strings.TrimSpace(strings.ToLower(t))
		return t == "1" || t == "true" || t == "yes" || t == "on"
	default:
		return false
	}
}

func getDuration(v any) time.Duration {
	switch t := v.(type) {
	case time.Duration:
		return t
	case int:
		return time.Duration(t) * time.Second
	case int64:
		return time.Duration(t) * time.Second
	case float64:
		return time.Duration(t) * time.Second
	case string:
		if d, err := time.ParseDuration(strings.TrimSpace(t)); err == nil {
			return d
		}
		var n int64
		if _, err := fmt.Sscanf(strings.TrimSpace(t), "%d", &n); err == nil {
			return time.Duration(n) * time.Second
		}
		return 0
	default:
		return 0
	}
}
