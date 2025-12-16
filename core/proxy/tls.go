package proxy

import (
	"crypto/tls"
	"net"

	"go-forward/core/utils"
)

// HandleTLS 处理 TLS 代理请求
func HandleTLS(conn net.Conn, forwardURLs []string, auth *utils.Auth) {
	// 生成自签名证书
	cert, err := utils.GetCertificate()
	if err != nil {
		conn.Close()
		return
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	tlsConn := tls.Server(conn, config)

	// 握手
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return
	}

	// 现在我们有了解密流。
	// 我们应该递归调用 handleConnection 来嗅探 TLS 内部的协议。
	// 例如 TLS 上的 SOCKS5，或 TLS 上的 HTTP。
	// 注意：这里需要调用 server.go 中的 handleConnection，但是它是私有的。
	// 我们需要将其导出或者在 server.go 中提供一个回调。
	// 为了简单起见，我们假设 HandleConnection 是导出的，或者我们在 server.go 中修改它。
	// 暂时先调用 HandleConnection (假设我们会重命名)
	HandleConnection(tlsConn, forwardURLs, auth, "")
}
