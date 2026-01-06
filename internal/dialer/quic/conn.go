package quic

import (
	"io"
	"net"
	"time"
)

type rwcConn struct {
	io.ReadWriteCloser
	local  net.Addr
	remote net.Addr
}

func (c *rwcConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (c *rwcConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (c *rwcConn) SetDeadline(t time.Time) error      { return nil }
func (c *rwcConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *rwcConn) SetWriteDeadline(t time.Time) error { return nil }

type combinedRWC struct {
	r io.ReadCloser
	w io.WriteCloser
}

func (c *combinedRWC) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *combinedRWC) Write(p []byte) (int, error) {
	return c.w.Write(p)
}

func (c *combinedRWC) Close() error {
	e1 := c.w.Close()
	e2 := c.r.Close()
	if e1 != nil {
		return e1
	}
	return e2
}
