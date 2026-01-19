package vless

import (
	"forward/inner/config"
	"forward/inner/dialer"
	vhandler "forward/inner/handler/vless"
	"forward/inner/listener"
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
