package proxy

import (
	"crypto/tls"
	"net"
	"net/http"

	"go-forward/core/utils"
)

func HandleHTTP2(conn net.Conn, forwardURL string, auth *utils.Auth, tlsConfig *tls.Config) {
	if tlsConfig == nil {
		cert, err := utils.GetCertificate()
		if err != nil {
			utils.Error("Failed to generate cert: %v", err)
			conn.Close()
			return
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}
	}

	tlsConn := tls.Server(conn, tlsConfig)

	server := &http.Server{
		Handler: &ProxyHandler{
			ForwardURL: forwardURL,
			Auth:       auth,
		},
	}

	l := &SingleConnListener{conn: tlsConn, ch: make(chan net.Conn, 1)}
	l.ch <- tlsConn

	server.Serve(l)
}
