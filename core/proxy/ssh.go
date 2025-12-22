package proxy

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-forward/core/utils"

	"golang.org/x/crypto/ssh"
)

var (
	hostKey     ssh.Signer
	hostKeyOnce sync.Once
)

func HandleSSH(conn net.Conn, forwardURLs []string, auth *utils.Auth, authorizedKeys []ssh.PublicKey) {
	config := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_10.2p1 Debian13",
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if auth != nil {
				if !auth.Validate(c.User(), string(pass)) {
					return nil, fmt.Errorf("password rejected for %q", c.User())
				}
			}
			return nil, nil
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if len(authorizedKeys) == 0 {
				return nil, fmt.Errorf("no authorized keys configured")
			}
			for _, k := range authorizedKeys {
				if bytes.Equal(k.Marshal(), pubKey.Marshal()) {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
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
		if newChannel.ChannelType() == "session" {
			channel, requests, err := newChannel.Accept()
			if err != nil {
				continue
			}
			go handleSSHSession(channel, requests, conn)
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
		go handleSSHChannel(channel, requests, targetAddr, forwardURLs, conn)
	}
}

func handleSSHSession(channel ssh.Channel, requests <-chan *ssh.Request, conn net.Conn) {
	defer channel.Close()

	go func() {
		for req := range requests {
			switch req.Type {
			case "shell", "pty-req", "env":
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}()

	remoteAddr := conn.RemoteAddr().String()
	host, _, _ := net.SplitHostPort(remoteAddr)
	now := time.Now().UTC()
	timeStr1 := now.Format("Mon Jan 02 15:04:05 MST 2006")
	timeStr2 := now.Format("Mon Jan 02 15:04:05 2006")

	msg := fmt.Sprintf(`Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.14.0-1016-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of %s

  System load:  3.03                Temperature:           -273.1 C
  Usage of /:   65.3%% of 192.69GB   Processes:             188
  Memory usage: 46%%                 Users logged in:       0
  Swap usage:   0%%                  IPv4 address for ens5: 172.30.20.10

 * Ubuntu Pro delivers the most comprehensive open source security and
   compliance features.

   https://ubuntu.com/aws/pro

Expanded Security Maintenance for Applications is not enabled.

79 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


*** System restart required ***
Last login: %s from %s
-bash: warning: setlocale: LC_ALL: cannot change locale (zh_CN.UTF-8)
`, timeStr1, timeStr2, host)

	channel.Write([]byte(strings.ReplaceAll(msg, "\n", "\r\n")))
	time.Sleep(time.Second)
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
	priv, err := utils.GenerateSSHKey()
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}
