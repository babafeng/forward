package phtdialer

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"forward/internal/dialer"
	"forward/internal/dialer/phtclient"
	"forward/internal/dialer/transportutil"
	"forward/internal/metadata"
)

type Metadata struct {
	AuthorizePath    string
	PushPath         string
	PullPath         string
	Host             string
	KeepAlivePeriod  time.Duration
	HandshakeTimeout time.Duration
	MaxIdleTimeout   time.Duration
	MaxStreams       int
	Secret           string
}

type Base struct {
	Options dialer.Options
	MD      Metadata

	mu      sync.Mutex
	clients map[string]*phtclient.Client
}

func NewBase(options dialer.Options) Base {
	return Base{
		Options: options,
		clients: make(map[string]*phtclient.Client),
	}
}

func (b *Base) Init(md metadata.Metadata) {
	parsed := dialer.ParsePHTTransportMetadata(md)
	b.MD.AuthorizePath = parsed.AuthorizePath
	b.MD.PushPath = parsed.PushPath
	b.MD.PullPath = parsed.PullPath
	b.MD.Host = parsed.Host
	b.MD.KeepAlivePeriod = parsed.KeepAlivePeriod
	b.MD.HandshakeTimeout = parsed.HandshakeTimeout
	b.MD.MaxIdleTimeout = parsed.MaxIdleTimeout
	b.MD.MaxStreams = parsed.MaxStreams
	b.MD.Secret = parsed.Secret
}

func (b *Base) Dial(ctx context.Context, addr string, newTransport func(host string) http.RoundTripper) (net.Conn, error) {
	b.mu.Lock()
	client := b.clients[addr]
	if client == nil {
		host := b.MD.Host
		if host == "" {
			host = transportutil.HostFromAddr(addr)
		}

		client = &phtclient.Client{
			Host:          host,
			HTTPClient:    &http.Client{Transport: newTransport(host)},
			AuthorizePath: b.MD.AuthorizePath,
			PushPath:      b.MD.PushPath,
			PullPath:      b.MD.PullPath,
			TLSEnabled:    true,
			Logger:        b.Options.Logger,
			Secret:        b.MD.Secret,
		}
		b.clients[addr] = client
	}
	b.mu.Unlock()

	return client.Dial(ctx, addr)
}

func Multiplex() bool {
	return true
}
