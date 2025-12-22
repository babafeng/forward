package proxy

import (
	"bufio"
	"crypto/tls"
	"net"

	"go-forward/core/utils"
)

// Start 启动代理服务器
func Start(listenURL string, forwardURLs []string) {
	scheme, auth, addr := utils.URLParse(listenURL)

	// 如果指定了 quic 协议，则只启动 QUIC (UDP) 监听
	if scheme == "quic" || scheme == "http3" {
		StartQUIC(addr, forwardURLs, auth)
		return
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		utils.Error("[Proxy] [Server] Listen error: %v", err)
		return
	}
	defer l.Close()

	utils.Info("[Proxy] [Server] Listening on %s (%s)", addr, scheme)

	for {
		conn, err := l.Accept()
		if err != nil {
			utils.Error("[Proxy] [Server] Accept error: %v", err)
			continue
		}
		go HandleConnection(conn, forwardURLs, auth, scheme)
	}
}

func HandleConnection(conn net.Conn, forwardURLs []string, auth *utils.Auth, scheme string) {
	// 1. 如果明确指定了协议，直接处理，不进行嗅探
	// 这样可以避免 bufio.NewReader 预读导致的数据丢失问题，
	// 也可以避免 SSH 服务端先发数据时的死锁问题。
	switch scheme {
	case "ssh":
		HandleSSH(conn, forwardURLs, auth)
		return
	case "http", "http1.1":
		HandleHTTP1(conn, forwardURLs, auth)
		return
	case "http2", "https":
		HandleHTTP2(conn, forwardURLs, auth)
		return
	case "socks5":
		HandleSocks5(conn, forwardURLs, auth)
		return
	case "tls":
		HandleTLS(conn, forwardURLs, auth)
		return
	}

	// 2. 嗅探协议类型 (用于自动检测或 scheme 为空/tcp 的情况)
	br := bufio.NewReader(conn)
	peek, _ := br.Peek(1)

	if len(peek) == 0 {
		conn.Close()
		return
	}

	// utils.Logging("[Proxy] [Server] peek: 0x%02x", peek[0])

	// socks5
	if peek[0] == 0x05 {
		HandleSocks5(newBufferedConn(conn, br), forwardURLs, auth)
		return
	}

	// https / tls
	if peek[0] == 0x16 {
		HandleTLS(newBufferedConn(conn, br), forwardURLs, auth)
		return
	}

	// ssh
	if peek[0] == 'S' {
		peek3, _ := br.Peek(3)
		if string(peek3) == "SSH" {
			HandleSSH(newBufferedConn(conn, br), forwardURLs, auth)
			return
		}
	}

	// 如果不是 socks5 / ssh / tls / https 默认使用 HTTP
	HandleHTTP1(newBufferedConn(conn, br), forwardURLs, auth)
}

type BufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufferedConn(c net.Conn, r *bufio.Reader) *BufferedConn {
	return &BufferedConn{Conn: c, r: r}
}

func (b *BufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *BufferedConn) ConnectionState() tls.ConnectionState {
	if tc, ok := b.Conn.(*tls.Conn); ok {
		return tc.ConnectionState()
	}
	return tls.ConnectionState{}
}
