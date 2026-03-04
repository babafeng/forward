package h3

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go"

	"forward/base/logging"
	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
)

var errMissingAddr = errors.New("missing listen address")
var errMissingTLS = errors.New("missing tls config")

type listenerMetadata struct {
	backlog          int
	keepAlivePeriod  time.Duration
	handshakeTimeout time.Duration
	maxIdleTimeout   time.Duration
	maxStreams       int
	secret           string
}

type Listener struct {
	addr    net.Addr
	server  *Server
	logger  *logging.Logger
	md      listenerMetadata
	options listener.Options
}

func init() {
	registry.ListenerRegistry().Register("h3", NewListener)
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Listener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *Listener) Init(md metadata.Metadata) error {
	l.parseMetadata(md)

	addr := l.options.Addr
	if addr == "" {
		return listener.NewBindError(errMissingAddr)
	}
	if l.options.TLSConfig == nil {
		return errMissingTLS
	}

	quicCfg := &quic.Config{
		Versions: []quic.Version{
			quic.Version1,
		},
	}
	if l.md.keepAlivePeriod > 0 {
		quicCfg.KeepAlivePeriod = l.md.keepAlivePeriod
	}
	if l.md.handshakeTimeout > 0 {
		quicCfg.HandshakeIdleTimeout = l.md.handshakeTimeout
	}
	if l.md.maxIdleTimeout > 0 {
		quicCfg.MaxIdleTimeout = l.md.maxIdleTimeout
	}
	if l.md.maxStreams > 0 {
		quicCfg.MaxIncomingStreams = int64(l.md.maxStreams)
	}

	opts := []ServerOption{
		TLSConfigServerOption(l.options.TLSConfig),
		BacklogServerOption(l.md.backlog),
		LoggerServerOption(l.logger),
	}
	if l.md.secret != "" {
		opts = append(opts, SecretServerOption(l.md.secret))
	}

	l.server = NewHTTP3Server(
		addr,
		quicCfg,
		opts...,
	)

	go func() {
		if err := l.server.ListenAndServe(); err != nil && l.logger != nil {
			if !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				l.logger.Error("HTTP3 listener error: %v", err)
			}
		}
	}()

	l.addr = l.server.Addr()
	return nil
}

func (l *Listener) Accept() (net.Conn, error) {
	if l.server == nil {
		return nil, listener.ErrClosed
	}
	conn, err := l.server.Accept()
	if err != nil {
		return nil, listener.NewAcceptError(err)
	}
	return conn, nil
}

func (l *Listener) Addr() net.Addr {
	if l.server == nil {
		return l.addr
	}
	if addr := l.server.Addr(); addr != nil {
		return addr
	}
	return l.addr
}

func (l *Listener) Close() error {
	if l.server == nil {
		return nil
	}
	if l.logger != nil && l.Addr() != nil {
		l.logger.Info("Listener closed %s", l.Addr().String())
	}
	return l.server.Close()
}

func (l *Listener) parseMetadata(md metadata.Metadata) {
	l.md.backlog = defaultBacklog
	if md == nil {
		return
	}
	if v := getInt(md.Get("backlog")); v > 0 {
		l.md.backlog = v
	}
	if getBool(md.Get("keepalive")) {
		if v := getDuration(md.Get("ttl")); v > 0 {
			l.md.keepAlivePeriod = v
		}
		if v := getDuration(md.Get("keepalive_period")); v > 0 {
			l.md.keepAlivePeriod = v
		}
	}
	if v := getDuration(md.Get("handshake_timeout")); v > 0 {
		l.md.handshakeTimeout = v
	}
	if v := getDuration(md.Get("max_idle_timeout")); v > 0 {
		l.md.maxIdleTimeout = v
	}
	if v := getInt(md.Get("max_streams")); v > 0 {
		l.md.maxStreams = v
	}
	if v := md.Get("secret"); v != nil {
		l.md.secret = fmt.Sprintf("%v", v)
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
