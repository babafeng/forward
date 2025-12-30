package proxy

import (
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

func HandleSSH(conn net.Conn, forwardURL string, auth *utils.Auth, authorizedKeys []ssh.PublicKey) {
	authenticator := utils.NewSSHAuthenticator(auth, authorizedKeys)
	config := &ssh.ServerConfig{
		ServerVersion:     "SSH-2.0-OpenSSH_10.2p1 Debian13",
		NoClientAuth:      !authenticator.HasPassword() && !authenticator.HasAuthorizedKeys(),
		PasswordCallback:  authenticator.PasswordCallback,
		PublicKeyCallback: authenticator.PublicKeyCallback,
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
		if newChannel.ChannelType() == "session" {
			channel, requests, err := newChannel.Accept()
			if err != nil {
				continue
			}
			go utils.ConfuseSSH(channel, requests, conn)
			continue
		}

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
		go handleSSHChannel(channel, requests, targetAddr, forwardURL, conn)
	}
}

func handleSSHChannel(channel ssh.Channel, requests <-chan *ssh.Request, targetAddr string, forwardURL string, originConn net.Conn) {
	defer channel.Close()
	go ssh.DiscardRequests(requests)

	targetConn, err := Dial("tcp", targetAddr, forwardURL)
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
	priv, err := utils.GenerateSSHKey()
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}
