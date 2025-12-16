package proxy

import (
	"io"
	"net"

	"go-forward/core/utils"
)

// HandleSocks5 处理 SOCKS5 代理请求
func HandleSocks5(conn net.Conn, forwardURLs []string, auth *utils.Auth) {
	defer conn.Close()

	// 握手
	// 我们已经 peek 了 0x05。
	// 读取版本和方法数
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
			conn.Write([]byte{0x01, 0x01}) // 失败
			return
		}

		conn.Write([]byte{0x01, 0x00}) // 成功

	} else {
		conn.Write([]byte{0x05, 0x00})
	}

	// 读取请求
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}

	cmd := header[1]
	if cmd != 0x01 { // CONNECT 命令
		return
	}

	targetAddr, err := utils.ReadSocks5Addr(conn, header[3])
	if err != nil {
		return
	}

	// 连接目标
	targetConn, err := Dial("tcp", targetAddr, forwardURLs)
	if err != nil {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	// 回复成功
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	utils.Transfer(conn, targetConn, targetAddr, "Proxy", "SOCKS5")
}
