package net

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
)

// packetBufPool caches buffers used by PacketStream.Write to avoid a heap
// allocation per write.  Max UDP payload is 65535 + 2 byte length header.
var packetBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2+65535)
		return &b
	},
}

type PacketStream struct {
	net.Conn
}

func NewPacketStream(conn net.Conn) *PacketStream {
	return &PacketStream{Conn: conn}
}

func (ps *PacketStream) Write(p []byte) (n int, err error) {
	if len(p) > 65535 {
		return 0, io.ErrShortBuffer
	}

	bp := packetBufPool.Get().(*[]byte)
	buf := (*bp)[:2+len(p)]
	binary.BigEndian.PutUint16(buf, uint16(len(p)))
	copy(buf[2:], p)

	_, err = ps.Conn.Write(buf)
	packetBufPool.Put(bp)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (ps *PacketStream) Read(p []byte) (n int, err error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(ps.Conn, header); err != nil {
		return 0, err
	}

	length := int(binary.BigEndian.Uint16(header))
	if length > len(p) {
		return 0, io.ErrShortBuffer
	}

	return io.ReadFull(ps.Conn, p[:length])
}
