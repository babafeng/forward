package forward

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-forward/core/proxy"
	"go-forward/core/utils"
)

// Start 启动端口转发服务
// 格式: [protocol://]local//remote
// 例如: :8080//1.2.3.4:80 或 tcp://:8080//1.2.3.4:80
func Start(listenURL string, forwardURL string) {
	var protocol, local, remote string
	if strings.HasPrefix(listenURL, "tcp://") {
		protocol = "tcp"
		listenURL = strings.TrimPrefix(listenURL, "tcp://")

	} else if strings.HasPrefix(listenURL, "udp://") {
		protocol = "udp"
		listenURL = strings.TrimPrefix(listenURL, "udp://")
	} else {
		protocol = "tcp"
	}

	var scheme, _, forwardAddr string
	if forwardURL != "" {
		scheme, _, forwardAddr = utils.URLParse(forwardURL)
	}

	parts := strings.Split(listenURL, "//")
	if len(parts) != 2 {
		utils.Error("Invalid forward URL: %s", listenURL)
		return
	}

	local = parts[0]
	remote = parts[1]

	// 规范化本地地址，如果没有 : 则添加
	if !strings.Contains(local, ":") {
		local = ":" + local
	}

	utils.Info("Forwarding %s %s --> %s via [%s %v]", protocol, local, remote, scheme, forwardAddr)

	if protocol == "udp" {
		startUDP(local, remote, forwardURL)
	} else {
		startTCP(local, remote, forwardURL)
	}
}

func startTCP(local, remote string, forwardURL string) {
	l, err := net.Listen("tcp", local)
	if err != nil {
		utils.Error("TCP Listen error: %v", err)
		return
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			utils.Error("TCP Accept error: %v", err)
			continue
		}
		go handleTCP(conn, remote, forwardURL)
	}
}

func handleTCP(conn net.Conn, remote string, forwardURL string) {
	defer conn.Close()

	rConn, err := proxy.Dial("tcp", remote, forwardURL)
	if err != nil {
		utils.Error("Dial error: %v", err)
		return
	}
	defer rConn.Close()

	utils.Transfer(conn, rConn, remote, "Forward", "TCP")
}

func startUDP(local, remote string, forwardURL string) {
	addr, err := net.ResolveUDPAddr("udp", local)
	if err != nil {
		utils.Error("UDP Resolve error: %v", err)
		return
	}
	var scheme, _, forwardAddr string
	if forwardURL != "" {
		scheme, _, forwardAddr = utils.URLParse(forwardURL)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		utils.Error("UDP Listen error: %v", err)
		return
	}
	defer conn.Close()

	utils.Info("UDP Forwarder listening on %s via [%s %v]", local, scheme, forwardAddr)

	// UDP 会话表: srcAddr -> net.Conn
	var sessions sync.Map
	cleanupTicker := time.NewTicker(2 * time.Minute)
	defer cleanupTicker.Stop()
	go func() {
		for range cleanupTicker.C {
			now := time.Now()
			sessions.Range(func(key, val any) bool {
				s := val.(*udpSession)
				if now.Sub(time.Unix(0, s.lastActive.Load())) > 2*time.Minute {
					s.conn.Close()
					sessions.Delete(key)
				}
				return true
			})
		}
	}()

	buf := utils.GetPacketBuffer()
	defer utils.PutPacketBuffer(buf)
	for {
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			utils.Error("UDP Read error: %v", err)
			continue
		}

		// 获取或创建会话
		key := srcAddr.String()
		val, ok := sessions.Load(key)
		var session *udpSession

		if !ok {
			utils.Info("Forwarding UDP %s -> %s --> %s via [%s %v]", key, local, remote, scheme, forwardAddr)
			remoteConn, err := proxy.Dial("udp", remote, forwardURL)
			if err != nil {
				utils.Error("UDP Dial error: %v", err)
				continue
			}

			session = &udpSession{conn: remoteConn}
			session.lastActive.Store(time.Now().UnixNano())
			sessions.Store(key, session)

			go func(s *udpSession, clientAddr *net.UDPAddr, k string) {
				defer s.conn.Close()
				defer sessions.Delete(k)

				rbuf := utils.GetPacketBuffer()
				defer utils.PutPacketBuffer(rbuf)
				for {
					s.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
					rn, err := s.conn.Read(rbuf)
					if err != nil {
						return
					}
					s.lastActive.Store(time.Now().UnixNano())
					_, err = conn.WriteToUDP(rbuf[:rn], clientAddr)
					if err != nil {
						return
					}
				}
			}(session, srcAddr, key)
		} else {
			session = val.(*udpSession)
		}

		session.conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		_, err = session.conn.Write(buf[:n])
		if err != nil {
			sessions.Delete(key)
			session.conn.Close()
			continue
		}
		session.lastActive.Store(time.Now().UnixNano())
	}
}

type udpSession struct {
	conn       net.Conn
	lastActive atomic.Int64
}
