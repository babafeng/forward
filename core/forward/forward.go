package forward

import (
	"net"
	"strings"

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

	utils.Info("Forwarding %s %s -> %s via %v", protocol, local, remote, forwardURLs)

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

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		utils.Error("UDP Listen error: %v", err)
		return
	}
	defer conn.Close()

	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			utils.Error("UDP Read error: %v", err)
			continue
		}
		go handleUDPPacket(conn, srcAddr, buf[:n], remote, forwardURLs)
	}
}

func handleUDPPacket(serverConn *net.UDPConn, srcAddr *net.UDPAddr, data []byte, remote string, forwardURLs []string) {
	rConn, err := proxy.Dial("udp", remote, forwardURLs)
	if err != nil {
		utils.Error("UDP Dial error: %v", err)
		return
	}
	defer rConn.Close()

	_, err = rConn.Write(data)
	if err != nil {
		return
	}

	respBuf := make([]byte, 65535)
	n, err := rConn.Read(respBuf)
	if err == nil {
		serverConn.WriteToUDP(respBuf[:n], srcAddr)
	}
}
