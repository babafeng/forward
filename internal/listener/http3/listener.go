package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"forward/base/logging"
	ictx "forward/internal/ctx"
	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
)

var errMissingAddr = errors.New("missing listen address")
var errMissingTLS = errors.New("missing tls config")

const defaultBacklog = 128

type listenerMetadata struct {
	backlog          int
	keepAlivePeriod  time.Duration
	handshakeTimeout time.Duration
	maxIdleTimeout   time.Duration
	maxStreams       int
}

type Listener struct {
	addr    net.Addr
	server  *http3.Server
	logger  *logging.Logger
	md      listenerMetadata
	options listener.Options

	cqueue  chan net.Conn
	errChan chan error
	mu      sync.Mutex
}

func init() {
	registry.ListenerRegistry().Register("http3", NewListener)
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

	network := "udp"
	if isIPv4(addr) {
		network = "udp4"
	}
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return listener.NewBindError(err)
	}
	l.addr = udpAddr

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

	tlsCfg := cloneTLSConfig(l.options.TLSConfig)
	ensureNextProtos(tlsCfg, []string{"h3"})
	tlsCfg = http3.ConfigureTLSConfig(tlsCfg)

	l.server = &http3.Server{
		Addr:       addr,
		TLSConfig:  tlsCfg,
		QUICConfig: quicCfg,
		Handler:    http.HandlerFunc(l.handleFunc),
	}

	l.cqueue = make(chan net.Conn, l.md.backlog)
	l.errChan = make(chan error, 1)

	go func() {
		if err := l.server.ListenAndServe(); err != nil && l.logger != nil {
			l.logger.Error("HTTP3 listener error: %v", err)
		}
		l.errChan <- http.ErrServerClosed
		close(l.errChan)
	}()

	return nil
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.cqueue:
		return conn, nil
	case err, ok := <-l.errChan:
		if !ok {
			err = listener.ErrClosed
		}
		return nil, err
	}
}

func (l *Listener) Addr() net.Addr {
	return l.addr
}

func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.server == nil {
		return nil
	}
	return l.server.Close()
}

func (l *Listener) handleFunc(w http.ResponseWriter, r *http.Request) {
	remoteAddr, _ := net.ResolveUDPAddr("udp", r.RemoteAddr)
	if remoteAddr == nil {
		remoteAddr = &net.UDPAddr{}
	}

	ctx := ictx.ContextWithMetadata(r.Context(), metadata.New(map[string]any{
		metadata.MetaHTTPRequest:        r,
		metadata.MetaHTTPResponseWriter: w,
	}))
	ctx, cancel := context.WithCancel(ctx)
	conn := &http3Conn{
		laddr:  l.addr,
		raddr:  remoteAddr,
		ctx:    ctx,
		cancel: cancel,
		closed: make(chan struct{}),
	}

	select {
	case l.cqueue <- conn:
	default:
		if l.logger != nil {
			l.logger.Warn("HTTP3 connection queue full, client %s discarded", r.RemoteAddr)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	<-conn.closed
}

func (l *Listener) parseMetadata(md metadata.Metadata) {
	parsed := listener.ParseTransportMetadata(md, defaultBacklog)
	l.md.backlog = parsed.Backlog
	l.md.keepAlivePeriod = parsed.KeepAlivePeriod
	l.md.handshakeTimeout = parsed.HandshakeTimeout
	l.md.maxIdleTimeout = parsed.MaxIdleTimeout
	l.md.maxStreams = parsed.MaxStreams
}

type http3Conn struct {
	laddr  net.Addr
	raddr  net.Addr
	ctx    context.Context
	cancel context.CancelFunc
	closed chan struct{}
	mu     sync.Mutex
}

func (c *http3Conn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *http3Conn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (c *http3Conn) LocalAddr() net.Addr              { return c.laddr }
func (c *http3Conn) RemoteAddr() net.Addr             { return c.raddr }
func (c *http3Conn) SetDeadline(time.Time) error      { return nil }
func (c *http3Conn) SetReadDeadline(time.Time) error  { return nil }
func (c *http3Conn) SetWriteDeadline(time.Time) error { return nil }

func (c *http3Conn) Close() error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil
	default:
		close(c.closed)
	}
	c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *http3Conn) Context() context.Context { return c.ctx }

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

func isIPv4(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.To4() != nil
}
