package ss

import (
	"bytes"
	"net"
	"testing"
	"time"

	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestSSPacketConnWriteAllocatesHeadroom(t *testing.T) {
	const frontHeadroom = 39
	const rearHeadroom = 16

	pc := &ssPacketConn{
		packetConn: &fakePacketConn{
			frontHeadroom: frontHeadroom,
			rearHeadroom:  rearHeadroom,
			t:             t,
		},
		dest: M.ParseSocksaddr("1.1.1.1:53"),
	}

	payload := []byte("payload")
	n, err := pc.Write(payload)
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned %d, want %d", n, len(payload))
	}
}

type fakePacketConn struct {
	frontHeadroom int
	rearHeadroom  int
	t             *testing.T
}

func (f *fakePacketConn) WritePacket(buffer *B.Buffer, _ M.Socksaddr) error {
	f.t.Helper()
	if got := buffer.Start(); got < f.frontHeadroom {
		f.t.Fatalf("buffer start = %d, want at least %d", got, f.frontHeadroom)
	}
	if !bytes.Equal(buffer.Bytes(), []byte("payload")) {
		f.t.Fatalf("buffer payload = %q, want %q", string(buffer.Bytes()), "payload")
	}
	buffer.ExtendHeader(f.frontHeadroom)
	buffer.Extend(f.rearHeadroom)
	return nil
}

func (f *fakePacketConn) ReadPacket(_ *B.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, nil
}

func (f *fakePacketConn) FrontHeadroom() int {
	return f.frontHeadroom
}

func (f *fakePacketConn) RearHeadroom() int {
	return f.rearHeadroom
}

func (f *fakePacketConn) Close() error {
	return nil
}

func (f *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (f *fakePacketConn) SetDeadline(time.Time) error {
	return nil
}

func (f *fakePacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (f *fakePacketConn) SetWriteDeadline(time.Time) error {
	return nil
}
