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
	port       string
	firstWrite bool
	firstRead  bool
	buf        []byte
}

func NewHttpObfsConn(conn net.Conn, host string, port string) *HttpObfsConn {
	if host == "" {
		host = "bing.com"
	}
	if port == "" {
		port = "80"
	}
	return &HttpObfsConn{
		Conn:       conn,
		host:       host,
		port:       port,
		firstWrite: true,
		firstRead:  true,
	}
}

func (c *HttpObfsConn) Write(b []byte) (int, error) {
	if c.firstWrite {
		c.firstWrite = false
		
		// 构造符合 simple-obfs HTTP 模式的纯文本头部。
		// 注意：
		// 1. 不能使用 Upgrade: websocket（那是 v2ray-plugin WS 的特征）
		// 2. 绝对不能使用 http.Request 输出 Content-Length，否则服务端读取完指定长度后，
		//    会把后续的 Shadowsocks 密文当作下一个 HTTP 请求解析，必然导致协议错乱和断流。
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n", c.host, c.port)
		
		// 一次性包裹写入
		payload := append([]byte(req), b...)
		n, err := c.Conn.Write(payload)
		
		// 抹平 Header 长度，对上层协议透明
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
		temp := make([]byte, 2048)
		// 必须循环读取，因为 TCP 是流式协议，HTTP 响应头极大概率会被网络分片
		for {
			n, err := c.Conn.Read(temp)
			if n > 0 {
				c.buf = append(c.buf, temp[:n]...)
				idx := bytes.Index(c.buf, []byte("\r\n\r\n"))
				if idx != -1 {
					c.firstRead = false
					c.buf = c.buf[idx+4:] // 抛弃头，保留 Shadowsocks 密文载荷
					break
				}
			}
			if err != nil {
				return 0, err
			}
		}
	}

	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		// 截断切片
		c.buf = c.buf[n:]
		// 优化：消费完后尽早释放引用空间
		if len(c.buf) == 0 {
			c.buf = nil
		}
		return n, nil
	}

	return c.Conn.Read(b)
}
