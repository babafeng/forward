package config

import (
	"time"

	"forward/internal/endpoint"
	"forward/internal/logging"
	"forward/internal/route"
)

const (
	DefaultDialTimeout       = 10 * time.Second
	DefaultDialKeepAlive     = 30 * time.Second
	DefaultUDPIdleTimeout    = 2 * time.Minute
	DefaultReadDeadline      = 1 * time.Second
	DefaultReadHeaderTimeout = 10 * time.Second

	DefaultBufferSize = 64 * 1024 // 64KB
	DefaultCopyBuffer = 32 * 1024 // 32KB

	DefaultMaxHeaderBytes = 1 << 20

	DefaultInitialBackoff   = 2 * time.Second
	DefaultMaxBackoff       = 30 * time.Second
	DefaultHandshakeTimeout = 5 * time.Second
	DefaultMaxConnections   = 4096
	DefaultMaxUDPSessions   = 1024

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

type NodeConfig struct {
	Name      string
	Listen    endpoint.Endpoint
	Listeners []endpoint.Endpoint
	Forward   *endpoint.Endpoint
	Insecure  bool
}

type Config struct {
	NodeName  string
	Listen    endpoint.Endpoint
	Listeners []endpoint.Endpoint
	LogLevel  logging.Level

	Forward *endpoint.Endpoint
	Nodes   []NodeConfig

	Route      *route.Config
	RouteStore *route.Store
	RoutePath  string

	Logger *logging.Logger

	UDPIdleTimeout    time.Duration
	DialTimeout       time.Duration
	DialKeepAlive     time.Duration
	ReadHeaderTimeout time.Duration
	MaxHeaderBytes    int

	Mode RunMode

	Insecure bool
}

func (c *Config) IsMode(m RunMode) bool {
	return c.Mode == m
}
