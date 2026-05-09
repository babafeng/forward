package structs

import (
	"context"
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
	Cancel    context.CancelFunc
}

func (c *QuicStreamConn) Close() error {
	var err error
	c.CloseOnce.Do(func() {
		err = c.Stream.Close()
		if c.Closer != nil {
			_ = c.Closer.CloseWithError(0, "")
		}
		if c.Cancel != nil {
			c.Cancel()
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

// CloseWrite 只关闭本 stream 的写端（发送 FIN），保留读端继续接收服务端回包。
// 语义对齐 *net.TCPConn.CloseWrite：让 base/io/net.Bidirectional 的半关闭
// 快路径能生效，免去 3s 无 CloseWrite fallback。
// quic-go 的 quic.Stream.Close 仅关闭 send side，读端保持可读，正好对应 CloseWrite。
func (c *QuicStreamConn) CloseWrite() error {
	if c.Stream == nil {
		return nil
	}
	return c.Stream.Close()
}
