package proxy

import (
	"crypto/tls"
	"net"

	"go-forward/core/utils"
)

// HandleTLS 处理 TLS 代理请求
func HandleTLS(conn net.Conn, forwardURLs []string, auth *utils.Auth, tlsConfig *tls.Config) {
	if tlsConfig == nil {
		// 生成自签名证书
		cert, err := utils.GetCertificate()
		if err != nil {
			conn.Close()
			return
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}
	}

	tlsConn := tls.Server(conn, tlsConfig)

	// 握手
	if err := tlsConn.Handshake(); err != nil {
		utils.Error("[Proxy] [TLS] Handshake failed: %v", err)
		tlsConn.Close()
		return
	}
	utils.Info("[Proxy] [TLS] Handshake success from %s", conn.RemoteAddr())

	HandleConnection(tlsConn, forwardURLs, auth, "", nil, nil)
}
