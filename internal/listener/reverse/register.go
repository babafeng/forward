package reverse

import (
	"context"
	"fmt"
	"net"
	"strings"

	"forward/internal/config"
	"forward/internal/dialer"
	hrev "forward/internal/handler/reverse"
	vhandler "forward/internal/handler/vless"
	"forward/internal/listener"
	lvless "forward/internal/listener/vless"
)

func init() {
	listener.Register("reverse", newRunner)
}

func newRunner(cfg config.Config, d dialer.Dialer) (listener.Runner, error) {
	if cfg.Listen.Query.Get("bind") != "true" {
		return nil, fmt.Errorf("reverse listener requires bind=true")
	}
	scheme := strings.ToLower(cfg.Listen.Scheme)
	switch scheme {
	case "tls", "quic", "http3", "https":
		h, err := hrev.NewServer(cfg)
		if err != nil {
			return nil, err
		}
		return New(cfg, h)
	case "vless+reality", "reality":
		h, err := hrev.NewServer(cfg)
		if err != nil {
			return nil, err
		}
		return newVlessListener(cfg, h)
	default:
		return nil, fmt.Errorf("reverse listener supports tls/https/quic/http3/vless+reality/reality, got %s", cfg.Listen.Scheme)
	}
}

type reversePipeDialer struct {
	handler Handler
}

func (d *reversePipeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	go d.handler.Handle(ctx, server)
	go func() {
		<-ctx.Done()
		_ = client.Close()
		_ = server.Close()
	}()
	return client, nil
}

func newVlessListener(cfg config.Config, revHandler Handler) (listener.Runner, error) {
	serverCfg, err := lvless.BuildServerConfig(cfg)
	if err != nil {
		return nil, err
	}

	pipeDialer := &reversePipeDialer{handler: revHandler}
	handler := vhandler.NewHandler(pipeDialer, cfg.Logger, nil, serverCfg.Validator)

	return lvless.NewListener(cfg, handler, serverCfg), nil
}
