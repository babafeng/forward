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
	if scheme == "quic" {
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
	// 嗅探协议类型
	br := bufio.NewReader(conn)
	peek, _ := br.Peek(1)

	if len(peek) == 0 {
		conn.Close()
		return
	}

	// 如果指定了 scheme 则强制检查，避免指定监听 SSH，也能使用 TLS
	if scheme != "" && scheme != "tcp" {
		switch scheme {
		case "tls":
			if peek[0] != 0x16 {
				utils.Logging("[Proxy] [Server] Expected TLS (0x16) but got 0x%02x", peek[0])
				conn.Close()
				return
			}
		case "socks5":
			if peek[0] != 0x05 {
				utils.Logging("[Proxy] [Server] Expected SOCKS5 (0x05) but got 0x%02x", peek[0])
				conn.Close()
				return
			}
		case "ssh":
			if peek[0] != 'S' {
				utils.Logging("[Proxy] [Server] Expected SSH ('S') but got 0x%02x", peek[0])
				conn.Close()
				return
			}
		}
	}

	// 如果监听时使用 -L :1080 没有指定 scheme 通过下面的嗅探逻辑判断协议类型
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
	HandleHTTP(newBufferedConn(conn, br), forwardURLs, auth)
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
