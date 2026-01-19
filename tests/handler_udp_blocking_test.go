package tests

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"forward/inner/config"
	"forward/inner/endpoint"
	"forward/inner/handler/udp"
	"forward/inner/logging"
)

// blockingConn simulates a connection that blocks on Write
type blockingConn struct {
	net.Conn
	writeBlockCh chan struct{}
	deadline     time.Time
}

func (c *blockingConn) Write(b []byte) (n int, err error) {
	if !c.deadline.IsZero() {
		timeout := time.Until(c.deadline)
		if timeout <= 0 {
			return 0, context.DeadlineExceeded
		}
		select {
		case <-c.writeBlockCh:
			return len(b), nil
		case <-time.After(timeout):
			return 0, context.DeadlineExceeded
		}
	}
	<-c.writeBlockCh
	return len(b), nil // Simulate successful write after blocking
}

func (c *blockingConn) Read(b []byte) (n int, err error) {
	// Block reading indefinitely for this test
	select {}
}

func (c *blockingConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *blockingConn) Close() error {
	return nil
}

func (c *blockingConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *blockingConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *blockingConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *blockingConn) SetWriteDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

type mockDialerBlocking struct {
	conn net.Conn
}

func (m *mockDialerBlocking) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return m.conn, nil
}

func TestUDPHandler_Handle_WriteBlocking(t *testing.T) {
	// Setup logger
	var logBuf bytes.Buffer
	logger := logging.New(logging.Options{Level: logging.LevelDebug, Out: &logBuf, Err: &logBuf})
	cfg := config.Config{
		Logger:         logger,
		Forward:        &endpoint.Endpoint{Scheme: "udp", Host: "127.0.0.1", Port: 5555},
		UDPIdleTimeout: 100 * time.Millisecond,
	}

	// Create a blocking connection
	blockCh := make(chan struct{})
	bConn := &blockingConn{writeBlockCh: blockCh}
	mDialer := &mockDialerBlocking{conn: bConn}

	h := udp.New(cfg, mDialer)
	defer h.Close()

	// Handle a packet. Since Handle writes to upstream synchronously (in current implementation),
	// and our upstream is blocking, Handle should block.
	// HOWEVER, Handle creates a session and starts a goroutine for reading, but the Write happens in Handle itself?
	// Let's check handler.go:
	// Handle(ctx, conn, pkt, src) -> s.upstream.Write(pkt) is called directly in Handle.
	// So Handle WILL block.

	ctx := context.Background()
	srcAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	// We need a proper UDP conn for Handle to use for replying, but we can mock or use a real one.
	// For this test, we don't expect reply yet.
	// But Handle takes *net.UDPConn. We can just pass nil since we are testing upstream write blocking,
	// and upstream write happens before any read loop logic that uses lconn.
	// Wait, session creation needs lconn.
	// Let's pass a dummy listener.
	lconn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer lconn.Close()

	done := make(chan struct{})
	go func() {
		h.Handle(ctx, lconn, []byte("hello"), srcAddr)
		close(done)
	}()

	// Wait a bit. Handle should block for at most 1s (deadline).
	// We wait 1.5s to ensure it unblocks.
	select {
	case <-done:
		// Success: Handle returned (due to deadline)
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("Handle blocked longer than deadline (1s), expected timeout")
	}

	// Now unblock to clean up (if it was still blocked, but it shouldn't be)
	close(blockCh)
	// <-done // Already selected above
}
