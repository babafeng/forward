package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"go-forward/core/utils"

	"golang.org/x/crypto/ssh"
)

// Dial 通过代理鏈连接到目标地址
func Dial(network, addr string, forwardURLs []string) (net.Conn, error) {
	forwardURLs = utils.FixURLScheme(forwardURLs)

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

	if len(forwardURLs) == 0 {
		return net.DialTimeout(network, addr, 10*time.Second)
	}

	firstURL := forwardURLs[0]
	u, err := url.Parse(firstURL)
	if err != nil {
		return nil, err
	}

	var conn net.Conn

	// 特殊处理 QUIC 协议作为第一跳
	if u.Scheme == "quic" || u.Scheme == "http3" {
		// 确定下一跳地址
		var nextAddr string
		if len(forwardURLs) == 1 {
			nextAddr = addr
		} else {
			nextU, _ := url.Parse(forwardURLs[1])
			nextAddr = nextU.Host
		}

		// 建立 QUIC 连接并执行 CONNECT
		conn, err = quicConnect(u.Host, nextAddr, u.User)
		if err != nil {
			return nil, err
		}

	} else {
		conn, err = net.DialTimeout("tcp", u.Host, 10*time.Second)
		if err != nil {
			return nil, err
		}
	}

	startIdx := 0
	if u.Scheme == "quic" || u.Scheme == "http3" {
		startIdx = 1
	}

	for i := startIdx; i < len(forwardURLs); i++ {
		currentURL := forwardURLs[i]
		u, _ := url.Parse(currentURL)

		// 确定下一跳地址：如果是最后一个节点，则下一跳是目标地址；否则是下一个代理节点的地址
		var nextAddr string
		if i == len(forwardURLs)-1 {
			nextAddr = addr
		} else {
			nextU, _ := url.Parse(forwardURLs[i+1])
			nextAddr = nextU.Host
		}

		// 解析 CA 证书参数
		var tlsConfig *tls.Config
		caFile := u.Query().Get("ca")
		if caFile != "" {
			pool, err := utils.LoadCA(caFile)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to load CA: %v", err)
			}
			tlsConfig = &tls.Config{
				RootCAs:    pool,
				ServerName: u.Hostname(),
			}
		} else {
			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         u.Hostname(),
			}
		}

		switch u.Scheme {
		case "socks5":
			if network == "udp" && i == len(forwardURLs)-1 {
				// 最后一跳如果是 UDP 且是 SOCKS5，使用 UDP Associate
				conn, err = socks5UDPAssociate(conn, nextAddr, u.User)
			} else {
				conn, err = socks5Connect(conn, nextAddr, u.User)
			}
		case "http":
			conn, err = httpConnect(conn, nextAddr, u.User)
		case "https":
			conn, err = tlsHandshake(conn, tlsConfig)
			if err != nil {
				conn.Close()
				return nil, err
			}
			utils.Debug("[Proxy] [Dialer] TLS Handshake success to %s", u.Host)
			conn, err = httpConnect(conn, nextAddr, u.User)
		case "ssh":
			conn, err = sshConnect(conn, u.Host, nextAddr, u.User)
		case "tls":
			conn, err = tlsHandshake(conn, tlsConfig)
			if err != nil {
				conn.Close()
				return nil, err
			}
			// TLS 握手成功后，默认使用 SOCKS5 协议继续连接下一跳
			utils.Debug("[Proxy] [Dialer] TLS Handshake success to %s %s %s", u.Host, nextAddr, u.User)

			if network == "udp" && i == len(forwardURLs)-1 {
				conn, err = socks5UDPAssociate(conn, nextAddr, u.User)
			} else {
				conn, err = socks5Connect(conn, nextAddr, u.User)
			}

		default:
			conn.Close()
			return nil, fmt.Errorf("Not supported scheme: %s", u.Scheme)
		}

		if err != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, err
		}
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

	return &Socks5UDPConn{
		tcpConn:    conn,
		udpConn:    udpConn,
		targetAddr: targetAddr,
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
}

func (c *Socks5UDPConn) Read(b []byte) (n int, err error) {
	buf := make([]byte, 65535)
	n, err = c.udpConn.Read(buf)
	if err != nil {
		return 0, err
	}

	if n < 10 {
		return 0, nil
	}

	atyp := buf[3]
	headLen := 0
	switch atyp {
	case 0x01: // IPv4
		headLen = 10
	case 0x03: // Domain
		domainLen := int(buf[4])
		headLen = 5 + domainLen + 2
	case 0x04: // IPv6
		headLen = 22
	default:
		return 0, fmt.Errorf("unknown address type: %d", atyp)
	}

	if n <= headLen {
		return 0, nil
	}

	copy(b, buf[headLen:n])
	return n - headLen, nil
}

func (c *Socks5UDPConn) Write(b []byte) (n int, err error) {
	buf := []byte{0x00, 0x00}
	buf = append(buf, 0x00)

	host, portStr, _ := net.SplitHostPort(c.targetAddr)
	port, _ := net.LookupPort("tcp", portStr) // udp port lookup is same

	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, 0x01)
		buf = append(buf, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		buf = append(buf, 0x04)
		buf = append(buf, ip6...)
	} else {
		buf = append(buf, 0x03)
		buf = append(buf, byte(len(host)))
		buf = append(buf, []byte(host)...)
	}

	buf = append(buf, byte(port>>8), byte(port))
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
		return nil, err
	}

	headerBuf := make([]byte, 0)
	b := make([]byte, 1)
	for {
		_, err := conn.Read(b)
		if err != nil {
			return nil, err
		}
		headerBuf = append(headerBuf, b[0])
		if strings.HasSuffix(string(headerBuf), "\r\n\r\n") {
			break
		}
		if len(headerBuf) > 4096 {
			return nil, fmt.Errorf("http connect response too large")
		}
	}

	resp := string(headerBuf)
	parts := strings.Split(resp, " ")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid http connect response")
	}

	if parts[1] != "200" {
		return nil, fmt.Errorf("http connect failed: %s", resp)
	}

	return conn, nil
}

func sshConnect(conn net.Conn, sshServerAddr, targetAddr string, user *url.Userinfo) (net.Conn, error) {
	username := "root"
	var authMethods []ssh.AuthMethod

	if user != nil {
		username = user.Username()
		if p, ok := user.Password(); ok {
			authMethods = append(authMethods, ssh.Password(p))
		}
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
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
		return nil, err
	}
	return tlsConn, nil
}
