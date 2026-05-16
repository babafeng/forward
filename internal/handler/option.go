package handler

import (
	"net/url"

	"forward/base/logging"
	"forward/internal/router"
)

type Options struct {
	Router router.Router
	Auth   *url.Userinfo
	Logger *logging.Logger
}

type Option func(opts *Options)

func RouterOption(r router.Router) Option {
	return func(opts *Options) {
		opts.Router = r
	}
}

func AuthOption(auth *url.Userinfo) Option {
	return func(opts *Options) {
		opts.Auth = auth
	}
}

func LoggerOption(logger *logging.Logger) Option {
	return func(opts *Options) {
		opts.Logger = logger
	}
}
