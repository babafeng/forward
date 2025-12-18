package reverse

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"go-forward/core/utils"

	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/ssh"
)

// StartServer 启动反向代理服务端（被客户端连接）
func StartServer(listenURL string) {
	scheme, auth, addr := utils.URLParse(listenURL)
	if scheme == "" {
		scheme = "quic"
	}

	s := strings.ToLower(scheme)
	// 检查是否为已知的代理协议
	proxySchemes := map[string]struct{}{
		"tls:":  {},
		"ssh:":  {},
		"quic:": {},
	}
	if _, exists := proxySchemes[s]; exists {
		utils.Info("Reverse Server only supports proxy protocols (tls, ssh, quic). Given: %s", scheme)
		return
	}

	if scheme == "quic" {
		utils.Info("Reverse Server listening on %s %s (UDP Only)", scheme, addr)
		startQUICServer(addr, auth)
		return
	} else {
		utils.Info("Reverse Server listening on %s %s (TCP Only)", scheme, addr)
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		utils.Error("Reverse Server Listen error: %v", err)
		return
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			utils.Error("Accept error: %v", err)
			continue
		}
		go handleConnection(conn, scheme, auth)
	}
}

func startQUICServer(addr string, auth *utils.Auth) {
	cert, err := utils.GetCertificate()
	if err != nil {
		utils.Error("Failed to generate certificate for QUIC: %v", err)
		return
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"reverse-quic"},
	}

	listener, err := quic.ListenAddr(addr, tlsConf, nil)
	if err != nil {
		utils.Error("QUIC Listen error: %v", err)
		return
	}

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			utils.Error("QUIC Accept error: %v", err)
			continue
		}
		go handleQUICConnection(conn, auth)
	}
}

func handleQUICConnection(conn *quic.Conn, auth *utils.Auth) {
	// 接受一个流作为控制连接
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return
	}
	// QUIC 建立后，内部流传输的是 SOCKS5 协议
	handleConnection(&quicStreamConn{Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, "socks5", auth)
}

type quicStreamConn struct {
	*quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.remote }

func handleConnection(conn net.Conn, scheme string, auth *utils.Auth) {
	// 嗅探协议
	br := bufio.NewReader(conn)
	peek, _ := br.Peek(1)

	if len(peek) == 0 {
		conn.Close()
		return
	}

	// Strict Protocol Enforcement
	if scheme == "tls" && peek[0] != 0x16 {
		utils.Error("Protocol mismatch: expected TLS (0x16), got 0x%02x", peek[0])
		conn.Close()
		return
	}
	if scheme == "ssh" && peek[0] != 'S' {
		utils.Error("Protocol mismatch: expected SSH ('S'), got 0x%02x", peek[0])
		conn.Close()
		return
	}

	// TLS (0x16)
	if peek[0] == 0x16 {
		handleTLS(utils.NewBufferedConn(conn, br), auth)
		return
	}

	// SSH ('S')
	if peek[0] == 'S' {
		handleSSH(utils.NewBufferedConn(conn, br), auth)
		return
	}

	// 默认 SOCKS5 (0x05) 或者直接处理
	handleSocks5Handshake(utils.NewBufferedConn(conn, br), auth)
}

func handleTLS(conn net.Conn, auth *utils.Auth) {
	cert, err := utils.GetCertificate()
	if err != nil {
		conn.Close()
		return
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	tlsConn := tls.Server(conn, config)

	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return
	}

	// TLS 握手成功后，继续处理内部协议 (SOCKS5)
	handleConnection(tlsConn, "socks5", auth)
}

func handleSSH(conn net.Conn, auth *utils.Auth) {
	config := &ssh.ServerConfig{
		NoClientAuth: auth == nil,
	}

	if auth != nil {
		config.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if auth.Validate(c.User(), string(pass)) {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		}
	}

	key, err := utils.GenerateSSHKey()
	if err != nil {
		conn.Close()
		return
	}
	signer, _ := ssh.NewSignerFromKey(key)
	config.AddHostKey(signer)

	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		conn.Close()
		return
	}

	go ssh.DiscardRequests(reqs)

	newChannel := <-chans
	if newChannel == nil {
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)

	// SSH 建立后，内部通道传输的是 SOCKS5 协议
	handleConnection(&sshChannelConn{Channel: channel, conn: conn}, "socks5", auth)
}

type sshChannelConn struct {
	ssh.Channel
	conn net.Conn
}

func (c *sshChannelConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *sshChannelConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *sshChannelConn) SetDeadline(t time.Time) error      { return nil }
func (c *sshChannelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *sshChannelConn) SetWriteDeadline(t time.Time) error { return nil }

func handleSocks5Handshake(conn net.Conn, auth *utils.Auth) {
	// 处理 SOCKS5 握手
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return
	}

	if buf[0] != 0x05 {
		conn.Close()
		return
	}

	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		conn.Close()
		return
	}

	if auth != nil {
		// 需要认证，检查客户端是否支持 0x02 (Username/Password)
		supportAuth := false
		for _, m := range methods {
			if m == 0x02 {
				supportAuth = true
				break
			}
		}

		if !supportAuth {
			conn.Write([]byte{0x05, 0xFF}) // No acceptable methods
			conn.Close()
			return
		}

		// 告诉客户端选择 0x02
		conn.Write([]byte{0x05, 0x02})

		// 读取认证请求
		// Ver(1) | Ulen(1) | User | Plen(1) | Pass
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			conn.Close()
			return
		}

		if header[0] != 0x01 { // Auth Version must be 1
			conn.Close()
			return
		}

		ulen := int(header[1])
		user := make([]byte, ulen)
		if _, err := io.ReadFull(conn, user); err != nil {
			conn.Close()
			return
		}

		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, plenBuf); err != nil {
			conn.Close()
			return
		}
		plen := int(plenBuf[0])
		pass := make([]byte, plen)
		if _, err := io.ReadFull(conn, pass); err != nil {
			conn.Close()
			return
		}

		if !auth.Validate(string(user), string(pass)) {
			conn.Write([]byte{0x01, 0x01}) // Failure
			conn.Close()
			return
		}

		conn.Write([]byte{0x01, 0x00}) // Success
	} else {
		// 无需认证
		conn.Write([]byte{0x05, 0x00})
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		conn.Close()
		return
	}

	cmd := header[1]
	if cmd == 0x02 { // BIND 命令
		handleBind(conn, header)
	} else {
		conn.Close()
	}
}

func handleBind(conn net.Conn, header []byte) {
	addrStr, err := utils.ReadSocks5Addr(conn, header[3])
	if err != nil {
		conn.Close()
		return
	}

	_, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		conn.Close()
		return
	}

	bindPort, _ := strconv.Atoi(portStr)

	// 在指定端口进行绑定
	l, err := net.Listen("tcp", ":"+portStr)
	if err != nil {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		conn.Close()
		return
	}

	// 回复成功
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, byte(bindPort >> 8), byte(bindPort)})

	// 生成 Session ID
	sessionID := generateSessionID()
	utils.Info("[Reverse] [%s] %s <--> :%d", sessionID, conn.RemoteAddr(), bindPort)

	conf := yamux.DefaultConfig()
	conf.EnableKeepAlive = true
	conf.KeepAliveInterval = 5 * time.Second

	session, err := yamux.Client(conn, conf)

	if err != nil {
		l.Close()
		conn.Close()
		return
	}

	// 监控 Session 状态，如果断开则关闭监听器
	go func() {
		_, err := session.Accept()
		if err != nil {
			utils.Info("Session %s disconnected (%v), closing listener :%d", sessionID, err, bindPort)
		} else {
			utils.Warn("Session %s received unexpected stream, closing listener :%d", sessionID, bindPort)
		}
		l.Close()
	}()

	// 接受绑定端口上的连接
	go func() {
		defer l.Close()
		defer session.Close()

		for {
			userConn, err := l.Accept()
			if err != nil {
				return
			}

			// 向客户端打开流
			stream, err := session.Open()
			if err != nil {
				userConn.Close()
				utils.Error("Session %s open stream failed: %v", sessionID, err)
				return
			}

			go func() {
				defer userConn.Close()
				defer stream.Close()
				utils.Transfer(userConn, stream, "tunnel", "Reverse", "TCP")
			}()
		}
	}()
}

func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
