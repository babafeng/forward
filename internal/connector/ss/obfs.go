package ss

import (
	"bytes"
	"fmt"
	"net"
)

// HttpObfsConn 实现了 shadowsocks 的 simple-obfs (http 模式)
type HttpObfsConn struct {
	net.Conn
	host       string
	firstWrite bool
	firstRead  bool
	buf        []byte
}

func NewHttpObfsConn(conn net.Conn, host string) *HttpObfsConn {
	if host == "" {
		host = "bing.com"
	}
	return &HttpObfsConn{
		Conn:       conn,
		host:       host,
		firstWrite: true,
		firstRead:  true,
		buf:        make([]byte, 0, 4096),
	}
}

func (c *HttpObfsConn) Write(b []byte) (int, error) {
	if c.firstWrite {
		c.firstWrite = false
		// 发送标准的 HTTP GET 请求，并将 shadowsocks 第一步的 payload 附加在末尾
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n", c.host)
		
		payload := append([]byte(req), b...)
		
		// 我们必须确保整体 payload 全部写入，即使底层的 Write 没有一次性写完
		// io.WriteString(c.Conn, req) 这种分开写可能会被 GFW 的特征检测发现
		n, err := c.Conn.Write(payload)
		
		// 减去我们注入的 HTTP 头的长度返回给上层，避免上层统计出错
		written := n - len(req)
		if written < 0 {
			written = 0
		}
		return written, err
	}
	return c.Conn.Write(b)
}

func (c *HttpObfsConn) Read(b []byte) (int, error) {
	if c.firstRead {
		temp := make([]byte, 1024)
		for {
			n, err := c.Conn.Read(temp)
			if n > 0 {
				c.buf = append(c.buf, temp[:n]...)
				// 寻找 HTTP 响应头的结束标志 \r\n\r\n
				idx := bytes.Index(c.buf, []byte("\r\n\r\n"))
				if idx != -1 {
					c.firstRead = false
					remaining := c.buf[idx+4:]
					c.buf = remaining
					break // 找到了完整 header，跳出循环
				}
			}
			if err != nil {
				return 0, err
			}
		}
	}

	// 如果内部缓存还有剩余的数据（属于 shadowsocks 的载荷），则优先读取
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	return c.Conn.Read(b)
}
