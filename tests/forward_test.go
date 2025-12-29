package tests

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"go-forward/core/forward"
)

func TestForwardTCP(t *testing.T) {
	targetAddr, stopServer := startMockTCPServer(t)
	defer stopServer()

	localAddr := fmt.Sprintf("127.0.0.1:%d", getFreePort(t))

	go forward.Start("tcp://"+localAddr+"//"+targetAddr, "")
	if err := waitForTCP(localAddr, 2*time.Second); err != nil {
		t.Fatalf("Forwarder not ready: %v", err)
	}

	conn, err := net.Dial("tcp", localAddr)
	if err != nil {
		t.Fatalf("Failed to connect to forwarder: %v", err)
	}
	defer conn.Close()

	msg := "hello tcp"
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if string(buf) != msg {
		t.Errorf("Expected %q, got %q", msg, string(buf))
	}
}

func TestForwardUDP(t *testing.T) {
	targetAddr, stopServer := startMockUDPServer(t)
	defer stopServer()

	localAddr := fmt.Sprintf("127.0.0.1:%d", getFreePort(t))

	go forward.Start("udp://"+localAddr+"//"+targetAddr, "")
	time.Sleep(200 * time.Millisecond)

	conn, err := net.Dial("udp", localAddr)
	if err != nil {
		t.Fatalf("Failed to connect to forwarder: %v", err)
	}
	defer conn.Close()

	msg := "hello udp"
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	buf := make([]byte, len(msg))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if string(buf[:n]) != msg {
		t.Errorf("Expected %q, got %q", msg, string(buf[:n]))
	}
}

func TestForwardStress(t *testing.T) {
	targetAddr, stopServer := startMockTCPServer(t)
	defer stopServer()

	localAddr := fmt.Sprintf("127.0.0.1:%d", getFreePort(t))

	go forward.Start("tcp://"+localAddr+"//"+targetAddr, "")
	if err := waitForTCP(localAddr, 2*time.Second); err != nil {
		t.Fatalf("Forwarder not ready: %v", err)
	}

	var wg sync.WaitGroup
	count := 30
	wg.Add(count)

	for i := 0; i < count; i++ {
		go func(id int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", localAddr)
			if err != nil {
				t.Errorf("Routine %d: Failed to connect: %v", id, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("stress test %d", id)
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write([]byte(msg)); err != nil {
				t.Errorf("Routine %d: Failed to write: %v", id, err)
				return
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Errorf("Routine %d: Failed to read: %v", id, err)
				return
			}
			if string(buf) != msg {
				t.Errorf("Routine %d: Data mismatch", id)
			}
		}(i)
	}
	wg.Wait()
}
