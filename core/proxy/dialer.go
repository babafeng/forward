package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go-forward/core/utils"

	"golang.org/x/crypto/ssh"
)

var defaultDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
}

// Dial 通过代理连接到目标地址
func Dial(network, addr string, forwardURL string) (net.Conn, error) {
	forwardURL = utils.FixURLScheme(forwardURL)

	if strings.Count(addr, ":") > 1 && !strings.Contains(addr, "[") && !strings.Contains(addr, "]") {
		lastColon := strings.LastIndex(addr, ":")
		if lastColon != -1 {
			host := addr[:lastColon]
			port := addr[lastColon+1:]
			if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
				addr = net.JoinHostPort(host, port)
			}
		}
	}

	if forwardURL == "" {
		return defaultDialer.Dial(network, addr)
	}

	forward, err := url.Parse(forwardURL)
	if err != nil {
		return nil, err
	}

	var conn net.Conn

	// 特殊处理 QUIC 协议
	if forward.Scheme == "quic" || forward.Scheme == "http3" {
		// QUIC 连接并执行 CONNECT
		conn, err = quicConnect(forward.Host, addr, forward.User)
		if err != nil {
			return nil, err
		}
	} else {
		conn, err = defaultDialer.Dial("tcp", forward.Host)
		if err != nil {
			return nil, err
		}
	}

	// 解析 CA 证书参数
	var tlsConfig *tls.Config
	caFile := forward.Query().Get("ca")
	if caFile != "" {
		pool, err := utils.LoadCA(caFile)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to load CA: %v", err)
		}
		tlsConfig = &tls.Config{
			RootCAs:    pool,
			ServerName: forward.Hostname(),
		}
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: utils.GetInsecure(),
			ServerName:         forward.Hostname(),
		}
	}

	switch forward.Scheme {
	case "socks5":
		if network == "udp" {
			// 如果是 UDP 且是 SOCKS5，使用 UDP Associate
			conn, err = socks5UDPAssociate(conn, addr, forward.User)
		} else {
			conn, err = socks5Connect(conn, addr, forward.User)
		}
	case "http":
		conn, err = httpConnect(conn, addr, forward.User)
	case "https":
		conn, err = tlsHandshake(conn, tlsConfig)
		if err != nil {
			return nil, err
		}
		utils.Debug("[Proxy] [Dialer] TLS Handshake success to %s", forward.Host)
		conn, err = httpConnect(conn, addr, forward.User)
	case "ssh":
		var signer ssh.Signer
		keyFile := forward.Query().Get("key")
		if keyFile != "" {
			password := forward.Query().Get("password")
			signer, err = utils.LoadSSHPrivateKey(keyFile, password)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to load SSH private key: %v", err)
			}
		}
		conn, err = sshConnect(conn, forward.Host, addr, forward.User, signer)
	case "tls":
		conn, err = tlsHandshake(conn, tlsConfig)
		if err != nil {
			return nil, err
		}
		// TLS 握手成功后，默认使用 SOCKS5 协议继续连接下一跳
		utils.Debug("[Proxy] [Dialer] TLS Handshake success to %s %s %s", forward.Host, addr, forward.User)

		if network == "udp" {
			conn, err = socks5UDPAssociate(conn, addr, forward.User)
		} else {
			conn, err = socks5Connect(conn, addr, forward.User)
		}
	case "quic", "http3":
		// Already handled above
	default:
		conn.Close()
		return nil, fmt.Errorf("Not supported scheme: %s", forward.Scheme)
	}

	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, err
	}

	return conn, nil
}

func socks5UDPAssociate(conn net.Conn, targetAddr string, user *url.Userinfo) (net.Conn, error) {
	// 1. 握手 (Auth)
	if err := socks5Auth(conn, user); err != nil {
		return nil, err
	}

	// 2. 发送 UDP ASSOCIATE (CMD=0x03)
	// DST.ADDR 和 DST.PORT 填 0.0.0.0:0
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	// 3. 读取响应
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return nil, err
	}

	if respHeader[1] != 0x00 {
		return nil, fmt.Errorf("socks5 udp associate failed with code: 0x%02x", respHeader[1])
	}

	// 读取 BND.ADDR 和 BND.PORT (代理服务器分配的 UDP 地址)
	bndAddr, err := utils.ReadSocks5Addr(conn, respHeader[3])
	if err != nil {
		return nil, err
	}

	proxyHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	bndHost, bndPort, _ := net.SplitHostPort(bndAddr)

	if bndHost == "0.0.0.0" || bndHost == "::" {
		bndAddr = net.JoinHostPort(proxyHost, bndPort)
	}

	udpConn, err := net.Dial("udp", bndAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial proxy udp %s: %v", bndAddr, err)
	}

	header, err := buildSocks5UDPHeader(targetAddr)
	if err != nil {
		udpConn.Close()
		return nil, err
	}

	return &Socks5UDPConn{
		tcpConn:    conn,
		udpConn:    udpConn,
		targetAddr: targetAddr,
		recvBuf:    make([]byte, 65535),
		header:     header,
	}, nil
}

func socks5Auth(conn net.Conn, user *url.Userinfo) error {
	methods := []byte{0x00}
	if user != nil {
		methods = append(methods, 0x02)
	}

	req := []byte{0x05, byte(len(methods))}
	req = append(req, methods...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != 0x05 {
		return fmt.Errorf("invalid socks version")
	}

	if buf[1] == 0x02 {
		if user == nil {
			return fmt.Errorf("server requires password auth but none provided")
		}
		u := user.Username()
		p, _ := user.Password()

		authReq := []byte{0x01, byte(len(u))}
		authReq = append(authReq, []byte(u)...)
		authReq = append(authReq, byte(len(p)))
		authReq = append(authReq, []byte(p)...)

		if _, err := conn.Write(authReq); err != nil {
			return err
		}

		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return err
		}

		if authResp[1] != 0x00 {
			return fmt.Errorf("socks5 auth failed")
		}
	} else if buf[1] != 0x00 {
		return fmt.Errorf("socks5 no acceptable methods")
	}
	return nil
}

func socks5Connect(conn net.Conn, targetAddr string, user *url.Userinfo) (net.Conn, error) {
	if err := socks5Auth(conn, user); err != nil {
		return nil, err
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}

	if err := utils.WriteSocks5Addr(conn, targetAddr); err != nil {
		return nil, err
	}

	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return nil, err
	}

	if respHeader[1] != 0x00 {
		return nil, fmt.Errorf("socks5 connect failed with code: 0x%02x", respHeader[1])
	}

	_, err := utils.ReadSocks5Addr(conn, respHeader[3])
	if err != nil {
		return nil, err
	}

	return conn, nil
}

type Socks5UDPConn struct {
	tcpConn    net.Conn
	udpConn    net.Conn
	targetAddr string
	recvBuf    []byte
	header     []byte
}

func (c *Socks5UDPConn) Read(b []byte) (n int, err error) {
	n, err = c.udpConn.Read(c.recvBuf)
	if err != nil {
		return 0, err
	}

	if n < 10 {
		return 0, nil
	}

	atyp := c.recvBuf[3]
	headLen := 0
	switch atyp {
	case 0x01: // IPv4
		headLen = 10
	case 0x03: // Domain
		domainLen := int(c.recvBuf[4])
		headLen = 5 + domainLen + 2
	case 0x04: // IPv6
		headLen = 22
	default:
		return 0, fmt.Errorf("unknown address type: %d", atyp)
	}

	if n <= headLen {
		return 0, nil
	}

	payloadLen := n - headLen
	if payloadLen <= 0 || len(b) == 0 {
		return 0, nil
	}
	if payloadLen > len(b) {
		copy(b, c.recvBuf[headLen:headLen+len(b)])
		return len(b), nil
	}
	copy(b, c.recvBuf[headLen:n])
	return payloadLen, nil
}

func (c *Socks5UDPConn) Write(b []byte) (n int, err error) {
	if c.header == nil {
		return 0, fmt.Errorf("socks5 udp header not initialized")
	}
	buf := make([]byte, 0, len(c.header)+len(b))
	buf = append(buf, c.header...)
	buf = append(buf, b...)
	_, err = c.udpConn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *Socks5UDPConn) Close() error {
	c.tcpConn.Close()
	return c.udpConn.Close()
}

func (c *Socks5UDPConn) LocalAddr() net.Addr {
	return c.udpConn.LocalAddr()
}

func (c *Socks5UDPConn) RemoteAddr() net.Addr {
	return c.udpConn.RemoteAddr()
}

func (c *Socks5UDPConn) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}

func (c *Socks5UDPConn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

func (c *Socks5UDPConn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}

func httpConnect(conn net.Conn, targetAddr string, user *url.Userinfo) (net.Conn, error) {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	if user != nil {
		u := user.Username()
		p, _ := user.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}

	req += "\r\n"

	_, err := conn.Write([]byte(req))
	if err != nil {
		return nil, fmt.Errorf("failed to write http connect request: %w", err)
	}

	reader := bufio.NewReader(conn)
	const maxHTTPConnectHeader = 4096
	var total int

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read http connect response: %w", err)
	}
	total += len(statusLine)
	if total > maxHTTPConnectHeader {
		return nil, fmt.Errorf("http connect response too large")
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read http connect response: %w", err)
		}
		total += len(line)
		if total > maxHTTPConnectHeader {
			return nil, fmt.Errorf("http connect response too large")
		}
		if line == "\r\n" {
			break
		}
	}

	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid http connect response")
	}
	if parts[1] != "200" {
		return nil, fmt.Errorf("http connect failed: %s", strings.TrimSpace(statusLine))
	}

	return newBufferedConn(conn, reader), nil
}

func buildSocks5UDPHeader(targetAddr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		port, err = net.LookupPort("udp", portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid target port: %w", err)
		}
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid target port: %d", port)
	}

	header := []byte{0x00, 0x00, 0x00}
	ipHost := host
	if i := strings.Index(host, "%"); i != -1 {
		ipHost = host[:i]
	}
	ip := net.ParseIP(ipHost)
	if ip4 := ip.To4(); ip4 != nil {
		header = append(header, 0x01)
		header = append(header, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		header = append(header, 0x04)
		header = append(header, ip6...)
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("domain too long: %s", host)
		}
		header = append(header, 0x03, byte(len(host)))
		header = append(header, []byte(host)...)
	}

	header = append(header, byte(port>>8), byte(port))
	return header, nil
}

func sshConnect(conn net.Conn, sshServerAddr, targetAddr string, user *url.Userinfo, signer ssh.Signer) (net.Conn, error) {
	username := "root"
	var authMethods []ssh.AuthMethod

	if user != nil {
		username = user.Username()
		if p, ok := user.Password(); ok {
			authMethods = append(authMethods, ssh.Password(p))
		}
	}

	if signer != nil {
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	if !utils.GetInsecure() {
		return nil, fmt.Errorf("SSH host key verification is required but not configured. Use --insecure to skip verification")
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, sshServerAddr, config)
	if err != nil {
		return nil, err
	}

	client := ssh.NewClient(c, chans, reqs)

	remoteConn, err := client.Dial("tcp", targetAddr)
	if err != nil {
		client.Close()
		return nil, err
	}

	return &sshClientConn{Conn: remoteConn, client: client}, nil
}

type sshClientConn struct {
	net.Conn
	client *ssh.Client
}

func (s *sshClientConn) Close() error {
	err := s.Conn.Close()
	s.client.Close()
	return err
}

func tlsHandshake(conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}
	return tlsConn, nil
}
