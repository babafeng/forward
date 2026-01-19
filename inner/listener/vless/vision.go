package vless

import (
	"encoding/binary"
	"io"
	"net"
)

type VisionConn struct {
	net.Conn
	remaining []byte
}

func NewVisionConn(c net.Conn) *VisionConn {
	return &VisionConn{
		Conn: c,
	}
}

func (c *VisionConn) Read(b []byte) (n int, err error) {
	if len(c.remaining) > 0 {
		n = copy(b, c.remaining)
		c.remaining = c.remaining[n:]
		return n, nil
	}

	header := make([]byte, 3)
	for {
		if _, err := io.ReadFull(c.Conn, header); err != nil {
			return 0, err
		}

		ctx := header[0]
		length := binary.BigEndian.Uint16(header[1:3])

		if ctx == 0x00 {
			if length > 0 {
				if _, err := io.CopyN(io.Discard, c.Conn, int64(length)); err != nil {
					return 0, err
				}
			}
			continue
		} else if ctx == 0x01 {
			readLen := int(length)
			if len(b) < readLen {

				payload := make([]byte, readLen)
				if _, err := io.ReadFull(c.Conn, payload); err != nil {
					return 0, err
				}

				n = copy(b, payload)
				c.remaining = payload[n:]
				return n, nil
			} else {
				n, err = io.ReadFull(c.Conn, b[:readLen])
				return n, err
			}
		} else {
			return 0, io.ErrUnexpectedEOF
		}
	}
}

func (c *VisionConn) Write(b []byte) (int, error) {
	total := len(b)
	offset := 0

	for offset < total {
		remaining := total - offset
		chunkSize := remaining
		if chunkSize > 65535 {
			chunkSize = 65535
		}

		header := []byte{0x01, 0x00, 0x00}
		binary.BigEndian.PutUint16(header[1:], uint16(chunkSize))

		if _, err := c.Conn.Write(header); err != nil {
			return offset, err
		}

		if _, err := c.Conn.Write(b[offset : offset+chunkSize]); err != nil {
			return offset, err
		}

		offset += chunkSize
	}

	return total, nil
}
