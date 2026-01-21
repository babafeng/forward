package http3

import (
	"context"
	"crypto/tls"
	"fmt"
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
	registry.DialerRegistry().Register("http3", NewDialer)
	registry.DialerRegistry().Register("quic", NewDialer)
}

type Dialer struct {
	options dialer.Options
	md      dialerMetadata

	mu      sync.Mutex
	clients map[string]*http.Client
}

type dialerMetadata struct {
	host             string
	keepAlivePeriod  time.Duration
	handshakeTimeout time.Duration
	maxIdleTimeout   time.Duration
	maxStreams       int
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Dialer{
		options: options,
		clients: make(map[string]*http.Client),
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
		ensureNextProtos(tlsCfg, []string{"h3"})

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

		tr := &http3.Transport{
			TLSClientConfig:    tlsCfg,
			QUICConfig:         quicCfg,
			DisableCompression: true,
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
			},
		}
		client = &http.Client{Transport: tr}
		d.clients[addr] = client
	}

	raddr, _ := net.ResolveTCPAddr("tcp", addr)
	if raddr == nil {
		raddr = &net.TCPAddr{}
	}

	return &clientConn{
		client:     client,
		localAddr:  &net.TCPAddr{},
		remoteAddr: raddr,
	}, nil
}

// Multiplex implements dialer.Multiplexer.
func (d *Dialer) Multiplex() bool {
	return true
}

type clientConn struct {
	client     *http.Client
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *clientConn) HTTPClient() *http.Client { return c.client }
func (c *clientConn) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (c *clientConn) Write([]byte) (int, error) {
	return 0, net.ErrClosed
}
func (c *clientConn) Close() error                     { return nil }
func (c *clientConn) LocalAddr() net.Addr              { return c.localAddr }
func (c *clientConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *clientConn) SetDeadline(time.Time) error      { return nil }
func (c *clientConn) SetReadDeadline(time.Time) error  { return nil }
func (c *clientConn) SetWriteDeadline(time.Time) error { return nil }

func (d *Dialer) parseMetadata(md metadata.Metadata) {
	if md == nil {
		return
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
	if v := getInt(md.Get("max_streams")); v > 0 {
		d.md.maxStreams = v
	}
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

func getInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(t), "%d", &n)
		return n
	default:
		return 0
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
