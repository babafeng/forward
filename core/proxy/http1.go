package proxy

import (
	"crypto/tls"
	"net"
	"net/http"

	"go-forward/core/utils"
)

// HandleHTTP1 处理 HTTP/1.1 代理请求
func HandleHTTP1(conn net.Conn, forwardURLs []string, auth *utils.Auth, tlsConfig *tls.Config) {
	if tlsConfig != nil {
		conn = tls.Server(conn, tlsConfig)
	}

	server := &http.Server{
		Handler: &ProxyHandler{
			ForwardURLs: forwardURLs,
			Auth:        auth,
		},
	}

	l := &SingleConnListener{conn: conn, ch: make(chan net.Conn, 1)}
	l.ch <- conn

	server.Serve(l)
}
