// Package h3 提供基于 HTTP/3（QUIC）的 PHT（Pseudo-HTTP Tunnel）传输实现。
// 底层连接逻辑由 base/transport/pht 包统一维护。
package h3

import (
	"net"
	"net/http"

	"forward/base/logging"
	"forward/base/transport/pht"
)

// NewClientConn 创建一个 PHT 客户端连接（HTTP/3 版）。
func NewClientConn(client *http.Client, pushURL, pullURL, secret string, remoteAddr net.Addr, logger *logging.Logger) net.Conn {
	return pht.NewClientConn(client, pushURL, pullURL, secret, remoteAddr, logger)
}

// NewServerConn 包装底层 net.Conn 并覆盖地址信息（HTTP/3 服务端版）。
func NewServerConn(conn net.Conn, localAddr, remoteAddr net.Addr) net.Conn {
	return pht.NewServerConn(conn, localAddr, remoteAddr)
}
