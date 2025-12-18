package forward

import (
	"net"
	"strings"
	"sync"
	"time"

	"go-forward/core/proxy"
	"go-forward/core/utils"
)

// Start 启动端口转发服务
// 格式: [protocol://]local//remote
// 例如: :8080//1.2.3.4:80 或 tcp://:8080//1.2.3.4:80
func Start(listenURL string, forwardURLs []string) {
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
	if len(forwardURLs) > 0 {
		scheme, _, forwardAddr = utils.URLParse(forwardURLs[0])
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
		startUDP(local, remote, forwardURLs)
	} else {
		startTCP(local, remote, forwardURLs)
	}
}

func startTCP(local, remote string, forwardURLs []string) {
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
		go handleTCP(conn, remote, forwardURLs)
	}
}

func handleTCP(conn net.Conn, remote string, forwardURLs []string) {
	defer conn.Close()

	rConn, err := proxy.Dial("tcp", remote, forwardURLs)
	if err != nil {
		utils.Error("Dial error: %v", err)
		return
	}
	defer rConn.Close()

	utils.Transfer(conn, rConn, remote, "Forward", "TCP")
}

func startUDP(local, remote string, forwardURLs []string) {
	addr, err := net.ResolveUDPAddr("udp", local)
	if err != nil {
		utils.Error("UDP Resolve error: %v", err)
		return
	}
	var scheme, _, forwardAddr string
	if len(forwardURLs) > 0 {
		scheme, _, forwardAddr = utils.URLParse(forwardURLs[0])
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

	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			utils.Error("UDP Read error: %v", err)
			continue
		}

		// 获取或创建会话
		key := srcAddr.String()
		val, ok := sessions.Load(key)
		var remoteConn net.Conn

		if !ok {
			utils.Info("Forwarding UDP %s -> %s --> %s via [%s %v]", key, local, remote, scheme, forwardAddr)
			remoteConn, err = proxy.Dial("udp", remote, forwardURLs)
			if err != nil {
				utils.Error("UDP Dial error: %v", err)
				continue
			}

			sessions.Store(key, remoteConn)

			go func(rc net.Conn, clientAddr *net.UDPAddr, k string) {
				defer rc.Close()
				defer sessions.Delete(k)

				rbuf := make([]byte, 65535)
				for {
					rc.SetReadDeadline(time.Now().Add(60 * time.Second))
					rn, err := rc.Read(rbuf)
					if err != nil {
						return
					}
					_, err = conn.WriteToUDP(rbuf[:rn], clientAddr)
					if err != nil {
						return
					}
				}
			}(remoteConn, srcAddr, key)
		} else {
			remoteConn = val.(net.Conn)
		}

		remoteConn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		_, err = remoteConn.Write(buf[:n])
		if err != nil {
			sessions.Delete(key)
			remoteConn.Close()
		}
	}
}
