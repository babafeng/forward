package reverse

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go-forward/core/utils"

	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/ssh"
)

var (
	reverseScheme string
	reverseAddr   string
	reverseHost   string
)

func StartClient(listenURL string, forwardURL string) {
	// 打删协议前缀
	if strings.HasPrefix(listenURL, "tcp://") {
		listenURL = strings.TrimPrefix(listenURL, "tcp://")
	} else if strings.HasPrefix(listenURL, "udp://") {
		listenURL = strings.TrimPrefix(listenURL, "udp://")
	}

	parts := strings.Split(listenURL, "//")
	if len(parts) != 2 {
		utils.Error("Invalid reverse client URL: %s", listenURL)
		return
	}

	remotePortStr := strings.TrimPrefix(parts[0], ":")
	remotePort, _ := strconv.Atoi(remotePortStr)
	localTarget := parts[1]
	serverURL := forwardURL

	reverseScheme, _, reverseAddr = utils.URLParse(serverURL)
	reverseHost = strings.Split(reverseAddr, ":")[0]
	utils.Info("[Reverse] %s:%d <--> %s via [%s %v]", reverseHost, remotePort, localTarget, reverseScheme, reverseAddr)

	backoff := 3 * time.Second
	for {
		err := connectAndServe(serverURL, remotePort, localTarget)
		if err != nil {
			utils.Error("Reverse connection error: %v. Retrying...", err)
			time.Sleep(backoff)
			if backoff < time.Minute {
				backoff *= 2
				if backoff > time.Minute {
					backoff = time.Minute
				}
			}
		}
	}
}

func connectAndServe(serverURL string, remotePort int, localTarget string) error {
	// 默认使用 TLS
	if !strings.Contains(serverURL, "://") {
		serverURL = "tls://" + serverURL
	}

	u, err := url.Parse(serverURL)
	if err != nil {
		return err
	}

	var conn net.Conn

	switch u.Scheme {
	case "quic":
		var err error
		conn, err = dialQUIC(u)
		if err != nil {
			return err
		}
	case "tls":
		var err error
		conn, err = dialTLS(u)
		if err != nil {
			return err
		}
	case "ssh":
		var err error
		conn, err = dialSSH(u)
		if err != nil {
			return err
		}
	case "tcp", "socks5":
		var err error
		conn, err = net.DialTimeout("tcp", u.Host, 10*time.Second)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
	defer conn.Close()

	// SOCKS5 Handshake
	var methods []byte
	user := u.User.Username()
	pass, _ := u.User.Password()

	if user != "" {
		methods = []byte{0x05, 0x02, 0x00, 0x02} // Support NoAuth (0x00) and UserPass (0x02)
	} else {
		methods = []byte{0x05, 0x01, 0x00} // Only NoAuth
	}

	if _, err := conn.Write(methods); err != nil {
		return err
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != 0x05 {
		return fmt.Errorf("invalid socks version")
	}

	switch buf[1] {
	case 0x02:
		// Password Auth
		req := []byte{0x01, byte(len(user))}
		req = append(req, []byte(user)...)
		req = append(req, byte(len(pass)))
		req = append(req, []byte(pass)...)

		if _, err := conn.Write(req); err != nil {
			return err
		}

		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return err
		}

		if authResp[1] != 0x00 {
			return fmt.Errorf("socks5 authentication failed")
		}
	case 0xFF:
		return fmt.Errorf("no acceptable methods")
	}

	// 发送 BIND 请求
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00}); err != nil {
		return err
	}
	if err := utils.WriteSocks5Addr(conn, fmt.Sprintf("0.0.0.0:%d", remotePort)); err != nil {
		return err
	}

	// 读取响应
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}

	if reply[1] != 0x00 {
		return fmt.Errorf("bind request rejected")
	}

	utils.Info("Reverse tunnel established with reverse server %s", reverseAddr)

	// 启动 Yamux 服务端
	session, err := yamux.Server(conn, nil)
	if err != nil {
		return err
	}
	defer session.Close()

	for {
		stream, err := session.Accept()
		if err != nil {
			return err
		}

		go func() {
			defer stream.Close()

			// 连接到本地目标
			localConn, err := net.DialTimeout("tcp", localTarget, 5*time.Second)
			if err != nil {
				utils.Error("Failed to dial local target %s: %v", localTarget, err)
				return
			}
			defer localConn.Close()

			utils.Transfer(stream, localConn, localTarget, "ReverseClient", "TCP")
		}()
	}
}

func dialQUIC(u *url.URL) (net.Conn, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: utils.GetInsecure(),
		NextProtos:         []string{"reverse-quic"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	qConn, err := quic.DialAddr(ctx, u.Host, tlsConf, nil)
	if err != nil {
		return nil, err
	}

	stream, err := qConn.OpenStreamSync(context.Background())
	if err != nil {
		qConn.CloseWithError(0, "")
		return nil, err
	}

	return &quicStreamConn{Stream: stream, local: qConn.LocalAddr(), remote: qConn.RemoteAddr()}, nil
}

func dialTLS(u *url.URL) (net.Conn, error) {
	return tls.Dial("tcp", u.Host, &tls.Config{InsecureSkipVerify: utils.GetInsecure()})
}

func dialSSH(u *url.URL) (net.Conn, error) {
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" {
		user = "root"
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	if !utils.GetInsecure() {
		return nil, fmt.Errorf("SSH host key verification is required but not configured. Use --insecure to skip verification")
	}

	conn, err := net.DialTimeout("tcp", u.Host, 10*time.Second)
	if err != nil {
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, u.Host, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	client := ssh.NewClient(c, chans, reqs)

	channel, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		client.Close()
		return nil, err
	}
	go ssh.DiscardRequests(reqs)

	return &sshChannelConn{Channel: channel, conn: conn}, nil
}
