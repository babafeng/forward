package quic

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

type RWCConn struct {
	io.ReadWriteCloser
	local  net.Addr
	remote net.Addr
	cancel context.CancelFunc

	mu    sync.Mutex
	timer *time.Timer
}

func (c *RWCConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (c *RWCConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (c *RWCConn) Close() error {
	err := c.ReadWriteCloser.Close()
	if c.cancel != nil {
		c.cancel()
	}
	return err
}

func (c *RWCConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}

	if t.IsZero() {
		return nil
	}

	d := time.Until(t)
	if d <= 0 {
		return c.Close()
	}

	c.timer = time.AfterFunc(d, func() {
		_ = c.Close()
	})
	return nil
}

func (c *RWCConn) SetReadDeadline(t time.Time) error {
	return c.SetDeadline(t)
}

func (c *RWCConn) SetWriteDeadline(t time.Time) error {
	return c.SetDeadline(t)
}

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
