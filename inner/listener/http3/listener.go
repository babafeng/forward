package http3

import (
	"context"
	stdhttp "net/http"
	"time"

	"github.com/quic-go/quic-go/http3"

	"forward/inner/config"
	"forward/base/logging"
)

type Handler interface {
	ServeHTTP(stdhttp.ResponseWriter, *stdhttp.Request)
}

type Listener struct {
	addr      string
	handler   Handler
	log       *logging.Logger
	proxyDesc string
	server    *http3.Server
}

func New(cfg config.Config, h Handler, srv *http3.Server) *Listener {
	proxy := "direct"
	if cfg.Forward != nil && cfg.Mode != config.ModePortForward {
		proxy = cfg.Forward.Address()
	}
	return &Listener{
		addr:      cfg.Listen.Address(),
		handler:   h,
		log:       cfg.Logger,
		proxyDesc: proxy,
		server:    srv,
	}
}

func (l *Listener) Run(ctx context.Context) error {
	l.log.Info("Forward HTTP/3 proxy listening on %s via %s", l.addr, l.proxyDesc)

	l.server.Addr = l.addr
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = l.server.Shutdown(shutdownCtx)
	}()

	if err := l.server.ListenAndServe(); err != nil && err != stdhttp.ErrServerClosed {
		l.log.Error("Forward http3 error: serve: %v", err)
		return err
	}
	return nil
}
