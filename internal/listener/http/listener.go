package http

import (
	"context"
	"crypto/tls"
	"errors"
	stdlog "log"
	"net"
	stdhttp "net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"forward/internal/config"
	"forward/internal/logging"
)

type Handler interface {
	ServeHTTP(stdhttp.ResponseWriter, *stdhttp.Request)
}

type Listener struct {
	addr      string
	scheme    string
	handler   Handler
	log       *logging.Logger
	proxyDesc string
	tlsConfig *tls.Config
}

func New(cfg config.Config, h Handler) *Listener {
	return NewWithTLS(cfg, h, nil)
}

func NewWithTLS(cfg config.Config, h Handler, tlsCfg *tls.Config) *Listener {
	proxy := "direct"
	if cfg.Proxy != nil {
		proxy = cfg.Proxy.Address()
	}
	return &Listener{
		addr:      cfg.Listen.Address(),
		scheme:    cfg.Listen.Scheme,
		handler:   h,
		log:       cfg.Logger,
		proxyDesc: proxy,
		tlsConfig: tlsCfg,
	}
}

func (l *Listener) Run(ctx context.Context) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", l.addr)
	if err != nil {
		l.log.Error("Forward http error: listen: %v", err)
		return err
	}
	if l.tlsConfig != nil {
		ln = tls.NewListener(ln, l.tlsConfig)
	}

	srv := &stdhttp.Server{
		Handler:      l.handler,
		TLSConfig:    l.tlsConfig,
		ErrorLog:     stdlog.New(&httpErrorLogWriter{log: l.log}, "", 0),
		BaseContext:  func(net.Listener) context.Context { return ctx },
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if l.tlsConfig != nil {
		_ = http2.ConfigureServer(srv, nil)
	}
	defer ln.Close()

	l.log.Info("Forward %s proxy listening on %s via %s", l.scheme, l.addr, l.proxyDesc)

	go func() {
		<-ctx.Done()
		// Graceful shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
		}
	}()

	if err := srv.Serve(ln); err != nil && err != stdhttp.ErrServerClosed && !errors.Is(err, net.ErrClosed) {
		l.log.Error("Forward http error: serve: %v", err)
		return err
	}
	return nil
}

type httpErrorLogWriter struct {
	log *logging.Logger
}

func (w *httpErrorLogWriter) Write(p []byte) (int, error) {
	if w == nil || w.log == nil {
		return len(p), nil
	}
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		w.log.Error("%s", msg)
	}
	return len(p), nil
}
