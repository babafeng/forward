package h2

import "forward/internal/listener/phtserver"

const (
	defaultBacklog           = phtserver.DefaultBacklog
	defaultReadBufferSize    = phtserver.DefaultReadBufferSize
	defaultReadTimeout       = phtserver.DefaultReadTimeout
	defaultReadHeaderTimeout = phtserver.DefaultReadHeaderTimeout
)

type Server = phtserver.Server
type ServerOption = phtserver.ServerOption

var (
	PathServerOption              = phtserver.PathServerOption
	BacklogServerOption           = phtserver.BacklogServerOption
	TLSConfigServerOption         = phtserver.TLSConfigServerOption
	ReadBufferSizeServerOption    = phtserver.ReadBufferSizeServerOption
	ReadTimeoutServerOption       = phtserver.ReadTimeoutServerOption
	ReadHeaderTimeoutServerOption = phtserver.ReadHeaderTimeoutServerOption
	MaxStreamsServerOption        = phtserver.MaxStreamsServerOption
	IdleTimeoutServerOption       = phtserver.IdleTimeoutServerOption
	ReadIdleTimeoutServerOption   = phtserver.ReadIdleTimeoutServerOption
	PingTimeoutServerOption       = phtserver.PingTimeoutServerOption
	LoggerServerOption            = phtserver.LoggerServerOption
	SecretServerOption            = phtserver.SecretServerOption
)

func NewServer(addr string, opts ...ServerOption) *Server {
	return phtserver.NewHTTP2Server(addr, opts...)
}
