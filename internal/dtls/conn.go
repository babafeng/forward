package dtls

import (
	"bytes"
	"net"

	"forward/base/pool"
)

const defaultBufferSize = 1200

type conn struct {
	net.Conn
	rbuf       bytes.Buffer
	bufferSize int
}

func Conn(c net.Conn, bufferSize int) net.Conn {
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}
	return &conn{
		Conn:       c,
		bufferSize: bufferSize,
	}
}

func (c *conn) Read(p []byte) (int, error) {
	if c.rbuf.Len() > 0 {
		return c.rbuf.Read(p)
	}

	if len(p) >= c.bufferSize {
		return c.Conn.Read(p)
	}

	buf := pool.GetWithSize(c.bufferSize)
	defer pool.Put(buf)

	n, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}

	copied := copy(p, buf[:n])
	if copied < n {
		c.rbuf.Write(buf[copied:n])
	}
	return copied, nil
}

func (c *conn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		nn := c.bufferSize
		if nn > len(p) {
			nn = len(p)
		}
		n, err := c.Conn.Write(p[:nn])
		total += n
		if err != nil {
			return total, err
		}
		p = p[n:]
	}
	return total, nil
}
