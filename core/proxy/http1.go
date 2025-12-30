package proxy

import (
	"crypto/tls"
	"net"
	"net/http"

	"go-forward/core/utils"
)

// HandleHTTP1 处理 HTTP/1.1 代理请求
func HandleHTTP1(conn net.Conn, forwardURL string, auth *utils.Auth, tlsConfig *tls.Config) {
	if tlsConfig != nil {
		conn = tls.Server(conn, tlsConfig)
	}

	utils.Info("[Proxy] [HTTP1] New connection from %s", conn.RemoteAddr())
	server := &http.Server{
		Handler: &ProxyHandler{
			ForwardURL: forwardURL,
			Auth:       auth,
		},
	}

	l := &SingleConnListener{conn: conn, ch: make(chan net.Conn, 1)}
	l.ch <- conn

	server.Serve(l)
}
