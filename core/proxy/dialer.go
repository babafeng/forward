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
	if u.Scheme == "quic" {
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
	if u.Scheme == "quic" {
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

		switch u.Scheme {
		case "socks5":
			conn, err = socks5Connect(conn, nextAddr, u.User)
		case "http":
			conn, err = httpConnect(conn, nextAddr, u.User)
		case "ssh":
			conn, err = sshConnect(conn, u.Host, nextAddr, u.User)
		case "tls":
			conn, err = tlsHandshake(conn, u.Hostname())
			if err != nil {
				conn.Close()
				return nil, err
			}
			// TLS 握手成功后，默认使用 SOCKS5 协议继续连接下一跳
			utils.Debug("TLS Handshake success to %s %s %s", u.Host, nextAddr, u.User)
			conn, err = socks5Connect(conn, nextAddr, u.User)

		default:
			conn.Close()
			return nil, fmt.Errorf("unknown proxy scheme: %s", u.Scheme)
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

func socks5Connect(conn net.Conn, targetAddr string, user *url.Userinfo) (net.Conn, error) {
	methods := []byte{0x00}
	if user != nil {
		methods = append(methods, 0x02)
	}

	req := []byte{0x05, byte(len(methods))}
	req = append(req, methods...)

	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	if buf[0] != 0x05 {
		return nil, fmt.Errorf("invalid socks version")
	}

	if buf[1] == 0x02 {
		if user == nil {
			return nil, fmt.Errorf("server requires password auth but none provided")
		}
		u := user.Username()
		p, _ := user.Password()

		authReq := []byte{0x01, byte(len(u))}
		authReq = append(authReq, []byte(u)...)
		authReq = append(authReq, byte(len(p)))
		authReq = append(authReq, []byte(p)...)

		if _, err := conn.Write(authReq); err != nil {
			return nil, err
		}

		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return nil, err
		}

		if authResp[1] != 0x00 {
			return nil, fmt.Errorf("socks5 auth failed")
		}
	} else if buf[1] != 0x00 {
		return nil, fmt.Errorf("socks5 no acceptable methods")
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

	// 读取响应
	// 简单读取直到 \r\n\r\n
	// 注意：这里可能读取过多，导致读取了后续的数据。
	// 严格来说应该使用 bufio.Reader，但是 conn 是 net.Conn。
	// 如果我们用 bufio 包装，我们需要返回包装后的 conn (BufferedConn)，否则后续读取会丢失 buffer 中的数据。
	// 这里为了简单，逐字节读取直到 header 结束。

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
	// HTTP/1.1 200 ...
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

	// 建立 SSH 客户端连接 (基于已有的 TCP 连接)
	c, chans, reqs, err := ssh.NewClientConn(conn, sshServerAddr, config)
	if err != nil {
		return nil, err
	}

	client := ssh.NewClient(c, chans, reqs)

	// 通过 SSH 隧道连接目标
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

func tlsHandshake(conn net.Conn, serverName string) (net.Conn, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}
