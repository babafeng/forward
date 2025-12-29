package utils

import "sync"

var streamBufPool = sync.Pool{
	New: func() any {
		return make([]byte, 32*1024)
	},
}

// GetStreamBuffer returns a reusable buffer for stream copy operations.
func GetStreamBuffer() []byte {
	return streamBufPool.Get().([]byte)
}

// PutStreamBuffer returns a stream buffer back to the pool.
func PutStreamBuffer(b []byte) {
	if b == nil {
		return
	}
	streamBufPool.Put(b[:cap(b)])
}

var packetBufPool = sync.Pool{
	New: func() any {
		return make([]byte, 65_535)
	},
}

// GetPacketBuffer returns a reusable buffer for packet-based copy operations.
func GetPacketBuffer() []byte {
	return packetBufPool.Get().([]byte)
}

// PutPacketBuffer returns a packet buffer back to the pool.
func PutPacketBuffer(b []byte) {
	if b == nil {
		return
	}
	packetBufPool.Put(b[:cap(b)])
}
