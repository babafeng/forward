package tcp

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.ListenerRegistry().Register("tcp", NewListener)
	registry.ListenerRegistry().Register("http", NewListener)
	registry.ListenerRegistry().Register("https", NewListener)
	registry.ListenerRegistry().Register("socks5", NewListener)
	registry.ListenerRegistry().Register("socks5h", NewListener)
}

type Listener struct {
	addr      string
	tlsConfig *tls.Config

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
		ln = tls.NewListener(ln, l.tlsConfig)
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
		return ln.Close()
	}
	return nil
}

var errMissingAddr = errors.New("missing listen address")
