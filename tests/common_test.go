package tests

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// Helper to get a free TCP port.
func getFreePort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve addr: %v", err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Mock TCP echo server.
func startMockTCPServer(t *testing.T) (string, func()) {
	t.Helper()
	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to listen on %s: %v", addr, err)
	}

	done := make(chan struct{})
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	return addr, func() {
		close(done)
		l.Close()
	}
}

// Mock UDP echo server.
func startMockUDPServer(t *testing.T) (string, func()) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Failed to listen UDP: %v", err)
	}

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			_, _ = conn.WriteToUDP(buf[:n], remoteAddr)
		}
	}()

	return conn.LocalAddr().String(), func() {
		close(done)
		conn.Close()
	}
}

func waitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return lastErr
}

