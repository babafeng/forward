package tests

import (
	"io"
	"testing"
	"time"

	"forward/inner/dialer/quic"
)

// mockRWC for testing RWCConn
type mockRWC struct {
	closed bool
}

func (m *mockRWC) Read(p []byte) (n int, err error) {
	if m.closed {
		return 0, io.EOF
	}
	return 0, nil
}

func (m *mockRWC) Write(p []byte) (n int, err error) {
	if m.closed {
		return 0, io.EOF
	}
	return len(p), nil
}

func (m *mockRWC) Close() error {
	m.closed = true
	return nil
}

func TestSetDeadlineCancel(t *testing.T) {
	mock := &mockRWC{}
	// Since RWCConn is now exported, we can use it.
	c := &quic.RWCConn{ReadWriteCloser: mock}

	// 1. Set short deadline
	c.SetDeadline(time.Now().Add(50 * time.Millisecond))

	// 2. Cancel it immediately
	c.SetDeadline(time.Time{})

	// 3. Wait past the original deadline
	time.Sleep(100 * time.Millisecond)

	if mock.closed {
		t.Fatal("Connection closed despite deadline cancellation")
	}

	// 4. Set new deadline and verify it closes
	c.SetDeadline(time.Now().Add(50 * time.Millisecond))
	time.Sleep(100 * time.Millisecond)

	if !mock.closed {
		t.Fatal("Connection should have closed after deadline")
	}
}

func TestSetDeadlineOverride(t *testing.T) {
	mock := &mockRWC{}
	c := &quic.RWCConn{ReadWriteCloser: mock}

	// 1. Set short deadline
	c.SetDeadline(time.Now().Add(50 * time.Millisecond))

	// 2. Override with longer deadline
	c.SetDeadline(time.Now().Add(200 * time.Millisecond))

	// 3. Wait past first deadline
	time.Sleep(100 * time.Millisecond)
	if mock.closed {
		t.Fatal("Connection closed early despite extended deadline")
	}

	// 4. Wait past second deadline
	time.Sleep(150 * time.Millisecond)
	if !mock.closed {
		t.Fatal("Connection should have closed after extended deadline")
	}
}
