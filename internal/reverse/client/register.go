package client

import (
	"fmt"

	"forward/internal/config"
)

var (
	registry = map[string]func(cfg config.Config) (Runner, error){}
)

func Register(scheme string, f func(cfg config.Config) (Runner, error)) {
	registry[scheme] = f
}

func New(cfg config.Config) (Runner, error) {
	if cfg.Forward == nil {
		return nil, fmt.Errorf("reverse client requires forward endpoint")
	}
	scheme := cfg.Forward.Scheme
	f, ok := registry[scheme]
	if !ok {
		return nil, fmt.Errorf("reverse client: unsupported forward scheme %s", scheme)
	}
	return f(cfg)
}

func init() {
	Register("https", func(cfg config.Config) (Runner, error) {
		return NewRunner(cfg)
	})
	Register("tls", func(cfg config.Config) (Runner, error) {
		return NewRunner(cfg)
	})
	Register("quic", func(cfg config.Config) (Runner, error) {
		return NewRunner(cfg)
	})
	Register("http3", func(cfg config.Config) (Runner, error) {
		return NewRunner(cfg)
	})
	Register("vless+reality", func(cfg config.Config) (Runner, error) {
		return NewRunner(cfg)
	})
	Register("reality", func(cfg config.Config) (Runner, error) {
		return NewRunner(cfg)
	})
}
