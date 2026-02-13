package tcp

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"time"

	"forward/base/logging"
	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
)

const (
	defaultHandshakeTimeout = 10 * time.Second
)

func init() {
	registry.ListenerRegistry().Register("tcp", NewListener)
	registry.ListenerRegistry().Register("http", NewListener)
	registry.ListenerRegistry().Register("https", NewListener)
	registry.ListenerRegistry().Register("http2", NewListener)
	registry.ListenerRegistry().Register("socks5", NewListener)
	registry.ListenerRegistry().Register("socks5h", NewListener)
}

type Listener struct {
	addr      string
	tlsConfig *tls.Config
	logger    *logging.Logger

	ln net.Listener
	mu sync.Mutex
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &Listener{
		addr:      options.Addr,
		tlsConfig: options.TLSConfig,
		logger:    options.Logger,
	}
}

func (l *Listener) Init(_ metadata.Metadata) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln != nil {
		return nil
	}
	if l.addr == "" {
		return listener.NewBindError(errMissingAddr)
	}
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return listener.NewBindError(err)
	}
	if l.tlsConfig != nil {
		ln = tls.NewListener(&timeoutListener{
			Listener: ln,
			timeout:  defaultHandshakeTimeout,
		}, l.tlsConfig)
	}
	l.ln = ln
	return nil
}

func (l *Listener) Accept() (net.Conn, error) {
	l.mu.Lock()
	ln := l.ln
	l.mu.Unlock()
	if ln == nil {
		return nil, listener.ErrClosed
	}
	conn, err := ln.Accept()
	if err != nil {
		return nil, listener.NewAcceptError(err)
	}
	// TLS 握手在 tls.NewListener 内部完成，deadline 由 timeoutListener 设置
	// 握手成功后清除 deadline 以避免影响后续数据传输
	if l.tlsConfig != nil {
		// 确保 TLS 握手已完成（tls.NewListener 会在 Accept 时完成握手）
		if tc, ok := conn.(*tls.Conn); ok {
			// 握手已在 Accept 时完成，现在可以安全清除 deadline
			if err := tc.Handshake(); err != nil {
				conn.Close()
				return nil, listener.NewAcceptError(err)
			}
		}
		conn.SetDeadline(time.Time{})
	}
	return conn, nil
}

type timeoutListener struct {
	net.Listener
	timeout time.Duration
}

func (l *timeoutListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(l.timeout))
	return conn, nil
}

func (l *Listener) Addr() net.Addr {
	l.mu.Lock()
	ln := l.ln
	l.mu.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Addr()
}

func (l *Listener) Close() error {
	l.mu.Lock()
	ln := l.ln
	l.ln = nil
	l.mu.Unlock()
	if ln != nil {
		if l.logger != nil {
			l.logger.Info("Listener closed %s", ln.Addr().String())
		}
		return ln.Close()
	}
	return nil
}

var errMissingAddr = errors.New("missing listen address")
