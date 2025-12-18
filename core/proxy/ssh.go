package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"go-forward/core/utils"

	"golang.org/x/crypto/ssh"
)

var (
	hostKey     ssh.Signer
	hostKeyOnce sync.Once
)

func HandleSSH(conn net.Conn, forwardURLs []string, auth *utils.Auth) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if auth != nil {
				if !auth.Validate(c.User(), string(pass)) {
					return nil, fmt.Errorf("password rejected for %q", c.User())
				}
			}
			return nil, nil
		},
	}

	key, err := getHostKey()
	if err != nil {
		utils.Error("[Proxy] [SSH] Failed to generate SSH host key: %v", err)
		conn.Close()
		return
	}
	config.AddHostKey(key)

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		utils.Error("[Proxy] [SSH] Handshake failed: %v", err)
		return
	}
	utils.Info("[Proxy] [SSH] Handshake success from %s", conn.RemoteAddr())
	defer sshConn.Close()

	// 处理全局请求
	go ssh.DiscardRequests(reqs)

	// 处理通道
	for newChannel := range chans {
		if newChannel.ChannelType() != "direct-tcpip" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		// 解析目标
		var d struct {
			DestAddr   string
			DestPort   uint32
			OriginAddr string
			OriginPort uint32
		}
		if err := ssh.Unmarshal(newChannel.ExtraData(), &d); err != nil {
			newChannel.Reject(ssh.ConnectionFailed, "error parsing payload")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		targetAddr := net.JoinHostPort(d.DestAddr, strconv.Itoa(int(d.DestPort)))
		utils.Info("[Proxy] [SSH] Channel request to %s", targetAddr)
		go handleSSHChannel(channel, requests, targetAddr, forwardURLs, conn)
	}
}

func handleSSHChannel(channel ssh.Channel, requests <-chan *ssh.Request, targetAddr string, forwardURLs []string, originConn net.Conn) {
	defer channel.Close()
	go ssh.DiscardRequests(requests)

	targetConn, err := Dial("tcp", targetAddr, forwardURLs)
	if err != nil {
		return
	}
	defer targetConn.Close()

	adapter := &sshChannelAdapter{Channel: channel, conn: originConn}
	utils.Transfer(adapter, targetConn, targetAddr, "Proxy", "SSH")
}

type sshChannelAdapter struct {
	ssh.Channel
	conn net.Conn
}

func (s *sshChannelAdapter) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *sshChannelAdapter) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func (s *sshChannelAdapter) SetDeadline(t time.Time) error {
	return nil
}

func (s *sshChannelAdapter) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *sshChannelAdapter) SetWriteDeadline(t time.Time) error {
	return nil
}

func getHostKey() (ssh.Signer, error) {
	var err error
	hostKeyOnce.Do(func() {
		hostKey, err = generateSSHKey()
	})
	return hostKey, err
}

func generateSSHKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}
