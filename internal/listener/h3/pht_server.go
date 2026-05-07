package h3

import (
	"time"

	"github.com/quic-go/quic-go"

	"forward/internal/listener/phtserver"
)

const (
	defaultBacklog           = phtserver.DefaultBacklog
	defaultReadBufferSize    = phtserver.DefaultReadBufferSize
	defaultReadTimeout       = phtserver.DefaultReadTimeout
	defaultReadHeaderTimeout = phtserver.DefaultReadHeaderTimeout
)

var (
	CleanupTickInterval = 30 * time.Second
	SessionIdleTimeout  = 60 * time.Second
)

type ServerOption = phtserver.ServerOption

type Server struct {
	*phtserver.Server
}

var (
	PathServerOption           = phtserver.PathServerOption
	BacklogServerOption        = phtserver.BacklogServerOption
	TLSConfigServerOption      = phtserver.TLSConfigServerOption
	EnableTLSServerOption      = phtserver.EnableTLSServerOption
	ReadBufferSizeServerOption = phtserver.ReadBufferSizeServerOption
	ReadTimeoutServerOption    = phtserver.ReadTimeoutServerOption
	LoggerServerOption         = phtserver.LoggerServerOption
	SecretServerOption         = phtserver.SecretServerOption
)

func NewServer(addr string, opts ...ServerOption) *Server {
	return &Server{Server: phtserver.NewServer(addr, opts...)}
}

func NewHTTP3Server(addr string, quicConfig *quic.Config, opts ...ServerOption) *Server {
	return &Server{Server: phtserver.NewHTTP3Server(addr, quicConfig, opts...)}
}

func (s *Server) ListenAndServe() error {
	syncCleanupConfig()
	return s.Server.ListenAndServe()
}

func syncCleanupConfig() {
	phtserver.CleanupTickInterval = CleanupTickInterval
	phtserver.SessionIdleTimeout = SessionIdleTimeout
}
