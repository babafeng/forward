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

type serverOptions struct {
	Auth           *utils.Auth
	TLSConfig      *tls.Config
	AuthorizedKeys []ssh.PublicKey
	SSHConfig      *ssh.ServerConfig
}

// StartServer 启动反向代理服务端（被客户端连接）
func StartServer(listenURL string) {
	scheme, auth, addr := utils.URLParse(listenURL)
	if scheme == "" {
		scheme = "quic"
	}

	baseOpts, err := utils.BuildServerOptions(listenURL, []string{"h2", "http/1.1"})
	if err != nil {
		utils.Error("[Reverse] [Server] option error: %v", err)
		return
	}
	opts := &serverOptions{
		Auth:           auth,
		TLSConfig:      baseOpts.TLSConfig,
		AuthorizedKeys: baseOpts.AuthorizedKeys,
	}

	s := strings.ToLower(scheme)
	proxySchemes := map[string]struct{}{
		"tls":  {},
		"ssh":  {},
		"quic": {},
	}
	if _, exists := proxySchemes[s]; !exists {
		utils.Error("[Reverse] [Server] only supports proxy protocols (tls, ssh, quic). Given: %s, %s", scheme, s)
		return
	}

	if scheme == "quic" {
		utils.Info("[Reverse] [Server] listening on %s %s (UDP Only)", scheme, addr)
		startQUICServer(addr, opts)
		return
	} else {
		utils.Info("[Reverse] [Server] listening on %s %s (TCP Only)", scheme, addr)
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
		go handleConnection(conn, scheme, opts)
	}
}

func startQUICServer(addr string, opts *serverOptions) {
	utils.Info("[Reverse] [QUIC] Incoming QUIC connection on %s", addr)
	tlsConfig := opts.TLSConfig
	tlsConfig.NextProtos = []string{"reverse-quic", "h3"}

	listener, err := quic.ListenAddr(addr, tlsConfig, nil)
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
		go handleQUICConnection(conn, opts)
	}
}

func handleQUICConnection(conn *quic.Conn, opts *serverOptions) {
	// 接受一个流作为控制连接
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		utils.Error("[Reverse] [QUIC] Accept stream error: %v", err)
		return
	}
	// QUIC 建立后，内部流传输的是 SOCKS5 协议
	handleConnection(&quicStreamConn{Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, "socks5", opts)
}

type quicStreamConn struct {
	*quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.remote }

func handleConnection(conn net.Conn, scheme string, opts *serverOptions) {
	utils.Debug("[Reverse] [Server] New connection from %s for scheme %s", conn.RemoteAddr(), scheme)

	br := bufio.NewReader(conn)
	peek, _ := br.Peek(1)

	if len(peek) == 0 {
		conn.Close()
		return
	}

	// Strict Protocol Enforcement
	if scheme == "tls" && peek[0] != 0x16 {
		utils.Error("[Reverse] [Server] Protocol mismatch: expected TLS (0x16), got 0x%02x", peek[0])
		return
	}
	if scheme == "ssh" && peek[0] != 'S' {
		utils.Error("[Reverse] [Server] Protocol mismatch: expected SSH ('S'), got 0x%02x", peek[0])
		return
	}

	// TLS (0x16)
	if peek[0] == 0x16 {
		utils.Debug("[Reverse] [Server] [TLS] Incoming TLS connection from %s", conn.RemoteAddr())
		handleTLS(utils.NewBufferedConn(conn, br), opts)
		return
	}

	// SSH ('S')
	if peek[0] == 'S' {
		utils.Debug("[Reverse] [Server] [SSH] Incoming SSH connection from %s", conn.RemoteAddr())
		handleSSH(utils.NewBufferedConn(conn, br), opts)
		return
	}

	// 默认 SOCKS5 (0x05) 或者直接处理
	handleSocks5Handshake(utils.NewBufferedConn(conn, br), opts)
}

func handleTLS(conn net.Conn, opts *serverOptions) {
	if opts == nil {
		opts = &serverOptions{}
	}
	utils.Info("[Reverse] [Server] [TLS] Incoming TLS connection from %s", conn.RemoteAddr())
	tlsConfig := opts.TLSConfig
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	tlsConn := tls.Server(conn, tlsConfig)

	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return
	}

	// TLS 握手成功后，继续处理内部协议 (SOCKS5)
	handleConnection(tlsConn, "socks5", opts)
}

func handleSSH(conn net.Conn, opts *serverOptions) {
	if opts == nil {
		opts = &serverOptions{}
	}
	config := opts.SSHConfig
	if config == nil {
		authenticator := utils.NewSSHAuthenticator(opts.Auth, opts.AuthorizedKeys)
		config = &ssh.ServerConfig{
			NoClientAuth:      !authenticator.HasPassword() && !authenticator.HasAuthorizedKeys(),
			PasswordCallback:  authenticator.PasswordCallback,
			PublicKeyCallback: authenticator.PublicKeyCallback,
		}
		key, _ := utils.GenerateSSHKey()
		signer, _ := ssh.NewSignerFromKey(key)
		config.AddHostKey(signer)
		opts.SSHConfig = config
	}

	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		utils.Error("[Reverse] [Server] [SSH] Handshake failed: %v", err)
		return
	}

	go ssh.DiscardRequests(reqs)

	newChannel := <-chans
	if newChannel == nil {
		utils.Error("[Reverse] [Server] [SSH] No channel request received")
		return
	}

	if newChannel.ChannelType() == "session" {
		channel, requests, err := newChannel.Accept()
		if err != nil {
			utils.Error("[Reverse] [Server] [SSH] Session channel accept error: %v", err)
			return
		}
		go utils.ConfuseSSH(channel, requests, conn)
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)

	// SSH 建立后，内部通道传输的是 SOCKS5 协议
	handleConnection(&sshChannelConn{Channel: channel, conn: conn}, "socks5", opts)
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

func handleSocks5Handshake(conn net.Conn, opts *serverOptions) {
	// 处理 SOCKS5 握手
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return
	}

	if buf[0] != 0x05 {
		return
	}

	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		conn.Close()
		return
	}

	if opts.Auth != nil {
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

		if !opts.Auth.Validate(string(user), string(pass)) {
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
	utils.Info("[Reverse] [Server] [%s] %s <--> :%d", sessionID, conn.RemoteAddr(), bindPort)

	conf := yamux.DefaultConfig()
	conf.EnableKeepAlive = true
	conf.KeepAliveInterval = 5 * time.Second

	session, err := yamux.Client(conn, conf)

	if err != nil {
		l.Close()
		conn.Close()
		utils.Error("[Reverse] [Server] Session %s yamux client error: %v", sessionID, err)
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
			utils.Debug("[Reverse] [Server] Accept connection on :%d", bindPort)
			userConn, err := l.Accept()
			if err != nil {
				utils.Error("[Reverse] [Server] Listener :%d accept error: %v", bindPort, err)
				return
			}

			// 向客户端打开流
			stream, err := session.Open()
			if err != nil {
				userConn.Close()
				utils.Error("Session %s %s:%s open stream failed: %v", sessionID, userConn.RemoteAddr(), userConn.LocalAddr(), err)
				return
			}

			utils.Debug("[Reverse] [Server] %s:%s --> %s:%s :%d", userConn.RemoteAddr(), userConn.LocalAddr(), stream.RemoteAddr(), stream.LocalAddr(), bindPort)

			go func() {
				defer userConn.Close()
				defer stream.Close()
				utils.Transfer(userConn, stream, "tunnel", "Reverse] [Server", "TCP")
			}()
		}
	}()
}

func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
