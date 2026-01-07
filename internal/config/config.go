package config

import (
	"time"

	"forward/internal/endpoint"
	"forward/internal/logging"
)

const (
	DefaultDialTimeout    = 10 * time.Second
	DefaultDialKeepAlive  = 30 * time.Second
	DefaultUDPIdleTimeout = 2 * time.Minute
	DefaultReadDeadline   = 1 * time.Second

	DefaultBufferSize = 64 * 1024 // 64KB
	DefaultCopyBuffer = 32 * 1024 // 32KB

	DefaultInitialBackoff = 2 * time.Second
	DefaultMaxBackoff     = 30 * time.Second

	CamouflageRealm     = `Authorization Required`
	CamouflagePageTitle = "403 Forbidden"
	CamouflagePageBody  = `<html>
<head><title>%s</title></head>
<body>
<center><h1>%s</h1></center>
<hr><center>nginx</center>
</body>
</html>`
)

type RunMode int

const (
	ModeUnknown RunMode = iota
	ModeProxyServer
	ModeReverseClient
	ModeReverseServer
	ModePortForward
)

func (m RunMode) String() string {
	switch m {
	case ModeProxyServer:
		return "proxy_server"
	case ModeReverseClient:
		return "reverse_client"
	case ModeReverseServer:
		return "reverse_server"
	case ModePortForward:
		return "port_forward"
	default:
		return "unknown"
	}
}

type Config struct {
	Listen    endpoint.Endpoint
	Listeners []endpoint.Endpoint
	LogLevel  logging.Level

	Proxy   *endpoint.Endpoint
	Forward *endpoint.Endpoint

	Logger *logging.Logger

	UDPIdleTimeout time.Duration
	DialTimeout    time.Duration
	DialKeepAlive  time.Duration

	Mode RunMode

	Insecure bool
}

func (c *Config) IsMode(m RunMode) bool {
	return c.Mode == m
}
