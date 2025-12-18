package utils

import (
	"bufio"
	"net"
)

// BufferedConn 包装 net.Conn 和 bufio.Reader 以支持读取已 peek 的数据
type BufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func NewBufferedConn(c net.Conn, r *bufio.Reader) *BufferedConn {
	return &BufferedConn{Conn: c, r: r}
}

func (b *BufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
