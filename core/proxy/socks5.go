package proxy

import (
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go-forward/core/utils"
)

func HandleSocks5(conn net.Conn, forwardURL string, auth *utils.Auth) {
	defer conn.Close()

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// 选择方法
	if auth != nil {
		// 检查客户端是否支持 0x02 (User/Pass)
		hasAuth := false
		for _, m := range methods {
			if m == 0x02 {
				hasAuth = true
				break
			}
		}

		if !hasAuth {
			conn.Write([]byte{0x05, 0xFF}) // 无可接受的方法
			return
		}

		conn.Write([]byte{0x05, 0x02})

		// 读取认证请求
		authHeader := make([]byte, 2)
		if _, err := io.ReadFull(conn, authHeader); err != nil {
			return
		}

		if authHeader[0] != 0x01 {
			return
		}

		ulen := int(authHeader[1])
		uname := make([]byte, ulen)
		if _, err := io.ReadFull(conn, uname); err != nil {
			return
		}

		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, plenBuf); err != nil {
			return
		}

		plen := int(plenBuf[0])
		passwd := make([]byte, plen)
		if _, err := io.ReadFull(conn, passwd); err != nil {
			return
		}

		if !auth.Validate(string(uname), string(passwd)) {
			utils.Logging("[Proxy] [SOCKS5] Auth failed for user: %s", uname)
			conn.Write([]byte{0x01, 0x01}) // 失败
			return
		}

		conn.Write([]byte{0x01, 0x00})

	} else {
		conn.Write([]byte{0x05, 0x00})
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}

	cmd := header[1]
	targetAddr, err := utils.ReadSocks5Addr(conn, header[3])
	if err != nil {
		utils.Error("[Proxy] [SOCKS5] Failed to read target address: %v", err)
		return
	}

	if cmd == 0x03 { // UDP ASSOCIATE
		handleUDP(conn, targetAddr)
		return
	}

	if cmd != 0x01 { // CONNECT 命令
		utils.Error("[Proxy] [SOCKS5] Unsupported command: 0x%02x", cmd)
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	targetConn, err := Dial("tcp", targetAddr, forwardURL)
	if err != nil {
		rep := utils.GetSocks5ReplyCode(err)
		utils.Error("[Proxy] [SOCKS5] Dial failed to %s: %v (Rep: 0x%02x)", targetAddr, err, rep)
		conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	utils.Transfer(conn, targetConn, targetAddr, "Proxy", "SOCKS5")
}

func handleUDP(conn net.Conn, clientAddr string) {
	utils.Info("[Proxy] [SOCKS5] UDP Associate requested from %s", clientAddr)

	// 启动 UDP 监听
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		utils.Error("[Proxy] [SOCKS5] ResolveUDPAddr failed: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	l, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		utils.Error("[Proxy] [SOCKS5] ListenUDP failed: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer l.Close()

	lAddr := l.LocalAddr().(*net.UDPAddr)
	utils.Info("[Proxy] [SOCKS5] UDP Listen on %s", lAddr)

	bndIP := lAddr.IP
	if bndIP.IsUnspecified() {
		localAddr := conn.LocalAddr().(*net.TCPAddr)
		bndIP = localAddr.IP
	}

	// 构造响应
	resp := []byte{0x05, 0x00, 0x00}
	if ip4 := bndIP.To4(); ip4 != nil {
		resp = append(resp, 0x01)
		resp = append(resp, ip4...)
	} else {
		resp = append(resp, 0x04)
		resp = append(resp, bndIP.To16()...)
	}

	port := lAddr.Port
	resp = append(resp, byte(port>>8), byte(port))

	if _, err := conn.Write(resp); err != nil {
		utils.Error("[Proxy] [SOCKS5] Write response failed: %v", err)
		return
	}

	go func() {
		buf := make([]byte, 1)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				l.Close()
				return
			}
		}
	}()

	buf := utils.GetPacketBuffer()
	defer utils.PutPacketBuffer(buf)

	targetConns := make(map[string]*udpTargetConn)
	var mu sync.Mutex

	var clientUDPAddr *net.UDPAddr

	stopCleanup := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stopCleanup:
				return
			case <-ticker.C:
				now := time.Now()
				mu.Lock()
				for addr, c := range targetConns {
					if now.Sub(time.Unix(0, c.lastUsed.Load())) > 2*time.Minute {
						c.conn.Close()
						delete(targetConns, addr)
					}
				}
				mu.Unlock()
			}
		}
	}()

	defer func() {
		close(stopCleanup)
		mu.Lock()
		for _, c := range targetConns {
			c.conn.Close()
		}
		mu.Unlock()
	}()

	for {
		n, rAddr, err := l.ReadFromUDP(buf)
		if err != nil {
			break
		}

		mu.Lock()
		if clientUDPAddr == nil {
			ipCopy := make(net.IP, len(rAddr.IP))
			copy(ipCopy, rAddr.IP)
			clientUDPAddr = &net.UDPAddr{IP: ipCopy, Port: rAddr.Port, Zone: rAddr.Zone}
		} else if clientUDPAddr.Port != rAddr.Port || !clientUDPAddr.IP.Equal(rAddr.IP) {
			mu.Unlock()
			continue
		}
		mu.Unlock()

		if n < 10 {
			continue
		}

		if buf[0] != 0x00 || buf[1] != 0x00 {
			continue // RSV must be 0
		}
		if buf[2] != 0x00 {
			continue // FRAG not supported
		}

		atyp := buf[3]
		var targetIP net.IP
		var targetPort int
		var headerLen int

		switch atyp {
		case 0x01: // IPv4
			targetIP = net.IP(buf[4:8])
			targetPort = int(buf[8])<<8 | int(buf[9])
			headerLen = 10
		case 0x03: // Domain
			dlen := int(buf[4])
			domain := string(buf[5 : 5+dlen])
			targetPort = int(buf[5+dlen])<<8 | int(buf[5+dlen+1])
			headerLen = 5 + dlen + 2

			// 解析域名
			addr, err := net.ResolveIPAddr("ip", domain)
			if err == nil {
				targetIP = addr.IP
			} else {
				utils.Error("[Proxy] [SOCKS5] Resolve domain %s failed: %v", domain, err)
				continue
			}
		case 0x04: // IPv6
			targetIP = net.IP(buf[4:20])
			targetPort = int(buf[20])<<8 | int(buf[21])
			headerLen = 22
		default:
			continue
		}

		if n <= headerLen {
			continue
		}

		data := buf[headerLen:n]
		targetAddrStr := net.JoinHostPort(targetIP.String(), strconv.Itoa(targetPort))
		utils.Debug("[Proxy] [SOCKS5] UDP packet %s -> %s %d bytes", rAddr, targetAddrStr, len(data))

		mu.Lock()
		entry, ok := targetConns[targetAddrStr]
		if !ok {
			rAddr, err := net.ResolveUDPAddr("udp", targetAddrStr)
			if err != nil {
				utils.Error("[Proxy] [SOCKS5] Resolve target %s failed: %v", targetAddrStr, err)
				mu.Unlock()
				continue
			}

			conn, err := net.DialUDP("udp", nil, rAddr)
			if err != nil {
				utils.Error("[Proxy] [SOCKS5] Dial UDP target %s failed: %v", targetAddrStr, err)
				mu.Unlock()
				continue
			}
			entry = &udpTargetConn{conn: conn}
			entry.lastUsed.Store(time.Now().UnixNano())
			targetConns[targetAddrStr] = entry

			go func(c *net.UDPConn, tAddr string) {
				defer c.Close()
				b := utils.GetPacketBuffer()
				defer utils.PutPacketBuffer(b)
				for {
					rn, _, err := c.ReadFromUDP(b)
					if err != nil {
						mu.Lock()
						delete(targetConns, tAddr)
						mu.Unlock()
						return
					}

					// 构造头部
					resp := []byte{0x00, 0x00, 0x00}

					// 解析 tAddr
					host, portStr, _ := net.SplitHostPort(tAddr)
					port, _ := strconv.Atoi(portStr)
					ip := net.ParseIP(host)

					if ip4 := ip.To4(); ip4 != nil {
						resp = append(resp, 0x01)
						resp = append(resp, ip4...)
					} else {
						resp = append(resp, 0x04)
						resp = append(resp, ip.To16()...)
					}
					resp = append(resp, byte(port>>8), byte(port))
					resp = append(resp, b[:rn]...)

					mu.Lock()
					addr := clientUDPAddr
					if entry, ok := targetConns[tAddr]; ok {
						entry.lastUsed.Store(time.Now().UnixNano())
					}
					mu.Unlock()

					if addr != nil {
						utils.Debug("[Proxy] [SOCKS5] UDP packet %s -> %s %d bytes", tAddr, addr, rn)
						l.WriteToUDP(resp, addr)
					}
				}
			}(entry.conn, targetAddrStr)
		}
		mu.Unlock()

		entry.lastUsed.Store(time.Now().UnixNano())
		entry.conn.Write(data)
	}
}

type udpTargetConn struct {
	conn     *net.UDPConn
	lastUsed atomic.Int64
}
