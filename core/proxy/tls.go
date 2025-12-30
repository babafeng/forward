package proxy

import (
	"crypto/tls"
	"net"

	"go-forward/core/utils"
)

// HandleTLS 处理 TLS 代理请求
func HandleTLS(conn net.Conn, forwardURL string, baseOpts *utils.ServerOptions, dispatcher *SniffDispatcher) {
	tlsConfig := baseOpts.TLSConfig
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	tlsConn := tls.Server(conn, tlsConfig)

	if err := tlsConn.Handshake(); err != nil {
		utils.Error("[Proxy] [TLS] Handshake failed: %v", err)
		tlsConn.Close()
		return
	}
	utils.Info("[Proxy] [TLS] Handshake success from %s", conn.RemoteAddr())

	HandleConnection(tlsConn, forwardURL, baseOpts, dispatcher)
}
