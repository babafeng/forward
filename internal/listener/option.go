package listener

import (
	"crypto/tls"

	"forward/inner/logging"
	"forward/internal/router"
)

type Options struct {
	Addr      string
	TLSConfig *tls.Config
	Logger    *logging.Logger
	Router    router.Router
}

type Option func(opts *Options)

func AddrOption(addr string) Option {
	return func(opts *Options) {
		opts.Addr = addr
	}
}

func TLSConfigOption(cfg *tls.Config) Option {
	return func(opts *Options) {
		opts.TLSConfig = cfg
	}
}

func LoggerOption(logger *logging.Logger) Option {
	return func(opts *Options) {
		opts.Logger = logger
	}
}

func RouterOption(r router.Router) Option {
	return func(opts *Options) {
		opts.Router = r
	}
}
