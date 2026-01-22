package dialer

import (
	"crypto/tls"
	"time"

	"forward/base/logging"
)

type Options struct {
	Addr      string
	Timeout   time.Duration
	TLSConfig *tls.Config
	Logger    *logging.Logger
}

type Option func(opts *Options)

func AddrOption(addr string) Option {
	return func(opts *Options) {
		opts.Addr = addr
	}
}

func TimeoutOption(timeout time.Duration) Option {
	return func(opts *Options) {
		opts.Timeout = timeout
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

type DialOptions struct {
	Logger *logging.Logger
}

type DialOption func(opts *DialOptions)

func LoggerDialOption(logger *logging.Logger) DialOption {
	return func(opts *DialOptions) {
		opts.Logger = logger
	}
}

type HandshakeOptions struct {
}

type HandshakeOption func(opts *HandshakeOptions)
