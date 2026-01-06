package structs

import (
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type closer interface {
	CloseWithError(code quic.ApplicationErrorCode, desc string) error
}

type QuicStreamConn struct {
	Stream    *quic.Stream
	Local     net.Addr
	Remote    net.Addr
	Closer    closer
	CloseOnce *sync.Once
}

func (c *QuicStreamConn) Close() error {
	var err error
	c.CloseOnce.Do(func() {
		err = c.Stream.Close()
		if c.Closer != nil {
			_ = c.Closer.CloseWithError(0, "")
		}
	})
	return err
}

func (c *QuicStreamConn) LocalAddr() net.Addr           { return c.Local }
func (c *QuicStreamConn) RemoteAddr() net.Addr          { return c.Remote }
func (c *QuicStreamConn) Read(p []byte) (int, error)    { return c.Stream.Read(p) }
func (c *QuicStreamConn) Write(p []byte) (int, error)   { return c.Stream.Write(p) }
func (c *QuicStreamConn) SetDeadline(t time.Time) error { return c.Stream.SetDeadline(t) }
func (c *QuicStreamConn) SetReadDeadline(t time.Time) error {
	return c.Stream.SetReadDeadline(t)
}
func (c *QuicStreamConn) SetWriteDeadline(t time.Time) error {
	return c.Stream.SetWriteDeadline(t)
}
