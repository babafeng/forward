package proxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"

	"go-forward/core/utils"
)

// HandleHTTP1 处理 HTTP/1.1 代理请求
func HandleHTTP1(conn net.Conn, forwardURL string, baseOpts *utils.ServerOptions) {
	auth := baseOpts.Auth
	tlsConfig := baseOpts.TLSConfig

	if tlsConfig != nil {
		conn = tls.Server(conn, tlsConfig)
	}

	utils.Info("[Proxy] [HTTP1] New connection from %s", conn.RemoteAddr())
	server := &http.Server{
		Handler: &ProxyHandler{
			ForwardURL: forwardURL,
			Auth:       auth,
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}

	listener := &SingleConnListener{conn: conn, ch: make(chan net.Conn, 1)}
	listener.ch <- conn

	server.Serve(listener)
}
