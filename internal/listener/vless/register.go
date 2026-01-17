package vless

import (
	"forward/internal/config"
	"forward/internal/dialer"
	vhandler "forward/internal/handler/vless"
	"forward/internal/listener"
)

func init() {
	listener.Register("vless+reality", newRunner)
	listener.Register("reality", newRunner)
}

func newRunner(cfg config.Config, d dialer.Dialer) (listener.Runner, error) {
	serverCfg, err := BuildServerConfig(cfg)
	if err != nil {
		return nil, err
	}

	handler := vhandler.NewHandler(d, cfg.Logger, cfg.RouteStore, serverCfg.Validator)

	return NewListener(cfg, handler, serverCfg), nil
}
