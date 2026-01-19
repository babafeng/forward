package connector

import (
	"net/url"
	"time"

	"forward/inner/logging"
)

type Options struct {
	Auth    *url.Userinfo
	Timeout time.Duration
	Logger  *logging.Logger
}

type Option func(opts *Options)

func AuthOption(auth *url.Userinfo) Option {
	return func(opts *Options) {
		opts.Auth = auth
	}
}

func TimeoutOption(timeout time.Duration) Option {
	return func(opts *Options) {
		opts.Timeout = timeout
	}
}

func LoggerOption(logger *logging.Logger) Option {
	return func(opts *Options) {
		opts.Logger = logger
	}
}

type ConnectOptions struct {
	Logger *logging.Logger
}

type ConnectOption func(opts *ConnectOptions)

func LoggerConnectOption(logger *logging.Logger) ConnectOption {
	return func(opts *ConnectOptions) {
		opts.Logger = logger
	}
}
