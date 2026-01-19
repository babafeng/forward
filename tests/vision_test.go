package tests

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"forward/inner/listener/vless"
)

type mockConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return m.r.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return m.w.Write(b)
}

func (m *mockConn) Close() error { return nil }

func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestVisionConn_Read(t *testing.T) {
	// Construct simulated Vision stream
	// Vision format: Context(1) | Length(2) | Payload
	// Context 0x00 = Padding, 0x01 = Data

	buf := new(bytes.Buffer)

	// Frame 1: Padding (5 bytes)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00) // Len hi
	buf.WriteByte(0x05) // Len lo
	buf.WriteString("PADDY")

	// Frame 2: Data "hello" (5 bytes)
	buf.WriteByte(0x01)
	buf.WriteByte(0x00)
	buf.WriteByte(0x05)
	buf.WriteString("hello")

	// Frame 3: Padding (2 bytes)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x02)
	buf.WriteString("XY")

	// Frame 4: Data " world" (6 bytes)
	buf.WriteByte(0x01)
	buf.WriteByte(0x00)
	buf.WriteByte(0x06)
	buf.WriteString(" world")

	mock := &mockConn{r: buf}
	vc := vless.NewVisionConn(mock)

	// Read all expected data
	out := make([]byte, 1024)
	n, err := vc.Read(out)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	got := string(out[:n])
	// Should be "hello" or "hello world" depending on implementation buffering
	// Our implementation might read one frame at a time or partial.
	// But `hello` is definitely first.

	// Since our implementation loops until it finds data, it should return "hello".
	// It stops after returning n > 0.

	if got != "hello" {
		// It's possible it reads more if we requested more?
		// No, implementation returns after one successful copy if n > 0.
		// Wait, if len(b) > frame payload, we read `readLen` into b and return.
		// So we return explicitly the frame content.
		t.Errorf("Expected 'hello', got '%s'", got)
	}

	// Read next part
	n, err = vc.Read(out)
	if err != nil {
		t.Fatalf("Read 2 failed: %v", err)
	}
	got = string(out[:n])
	if got != " world" {
		t.Errorf("Expected ' world', got '%s'", got)
	}
}

func TestVisionConn_Write(t *testing.T) {
	buf := new(bytes.Buffer)
	mock := &mockConn{w: buf}
	vc := vless.NewVisionConn(mock)

	payload := []byte("hello vision")
	n, err := vc.Write(payload)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Write length mismatch: got %d, want %d", n, len(payload))
	}

	// Verify wire format
	// 0x01 | Len(hi) | Len(lo) | payload
	wantLen := 3 + len(payload)
	if buf.Len() != wantLen {
		t.Fatalf("Wire length mismatch: got %d, want %d", buf.Len(), wantLen)
	}

	wire := buf.Bytes()
	if wire[0] != 0x01 {
		t.Errorf("Wrong context: %x", wire[0])
	}

	plen := int(wire[1])<<8 | int(wire[2])
	if plen != len(payload) {
		t.Errorf("Wrong payload length: %d", plen)
	}

	if string(wire[3:]) != string(payload) {
		t.Errorf("Wrong payload: %s", string(wire[3:]))
	}
}
