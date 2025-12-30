package proxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"

	"go-forward/core/utils"
)

func HandleHTTP2(conn net.Conn, forwardURL string, baseOpts *utils.ServerOptions) {
	auth := baseOpts.Auth
	tlsConfig := baseOpts.TLSConfig

	tlsConn := tls.Server(conn, tlsConfig)

	server := &http.Server{
		Handler: &ProxyHandler{
			ForwardURL: forwardURL,
			Auth:       auth,
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}

	l := &SingleConnListener{conn: tlsConn, ch: make(chan net.Conn, 1)}
	l.ch <- tlsConn

	server.Serve(l)
}
