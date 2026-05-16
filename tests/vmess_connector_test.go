package tests

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess/encoding"

	_ "unsafe"
)

//go:linkname vmessConnRead forward/internal/connector/vmess.(*vmessConn).Read
func vmessConnRead(c *vmessConnMirror, p []byte) (int, error)

type vmessConnMirror struct {
	net.Conn
	session    *encoding.ClientSession
	request    *protocol.RequestHeader
	bodyWriter buf.Writer
	reader     *buf.BufferedReader
	initOnce   sync.Once
	initErr    error
}

type stubConn struct{}

func (stubConn) Read([]byte) (int, error)           { return 0, io.EOF }
func (stubConn) Write(p []byte) (int, error)        { return len(p), nil }
func (stubConn) Close() error                       { return nil }
func (stubConn) LocalAddr() net.Addr                { return nil }
func (stubConn) RemoteAddr() net.Addr               { return nil }
func (stubConn) SetDeadline(_ time.Time) error      { return nil }
func (stubConn) SetReadDeadline(_ time.Time) error  { return nil }
func (stubConn) SetWriteDeadline(_ time.Time) error { return nil }

type oneShotReader struct {
	payload []byte
	sent    bool
}

func (r *oneShotReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.sent {
		return nil, io.EOF
	}
	r.sent = true
	b := buf.New()
	_, _ = b.Write(r.payload)
	return buf.MultiBuffer{b}, nil
}

func TestVMessConnRead_NoTailLoss(t *testing.T) {
	c := &vmessConnMirror{
		Conn:   stubConn{},
		reader: &buf.BufferedReader{Reader: &oneShotReader{payload: []byte("abcdef")}},
	}
	c.initOnce.Do(func() {})

	part1 := make([]byte, 2)
	n1, err := vmessConnRead(c, part1)
	if err != nil {
		t.Fatalf("first read failed: %v", err)
	}
	if got := string(part1[:n1]); got != "ab" {
		t.Fatalf("first read got %q, want %q", got, "ab")
	}

	part2 := make([]byte, 4)
	n2, err := vmessConnRead(c, part2)
	if err != nil {
		t.Fatalf("second read failed: %v", err)
	}
	if got := string(part2[:n2]); got != "cdef" {
		t.Fatalf("second read got %q, want %q", got, "cdef")
	}
}
