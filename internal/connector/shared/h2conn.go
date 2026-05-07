package shared

import (
	"io"
	"net"
	"time"
)

// H2Conn 是 HTTP/2 和 HTTP/3 代理连接的通用实现
type H2Conn struct {
	R         io.Reader
	W         io.WriteCloser
	CloseFunc func() error
}

func (c *H2Conn) Read(p []byte) (int, error)         { return c.R.Read(p) }
func (c *H2Conn) Write(p []byte) (int, error)        { return c.W.Write(p) }
func (c *H2Conn) Close() error                       { return c.CloseFunc() }
func (c *H2Conn) LocalAddr() net.Addr                { return nil }
func (c *H2Conn) RemoteAddr() net.Addr               { return nil }
func (c *H2Conn) SetDeadline(time.Time) error        { return nil }
func (c *H2Conn) SetReadDeadline(time.Time) error    { return nil }
func (c *H2Conn) SetWriteDeadline(time.Time) error   { return nil }
