package tests

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"go-forward/core/reverse"
	"go-forward/core/utils"
)

func TestReverseTCP(t *testing.T) {
	targetAddr, stopTarget := startMockTCPServer(t)
	defer stopTarget()

	serverAddr := fmt.Sprintf("127.0.0.1:%d", getFreePort(t))
	go reverse.StartServer(fmt.Sprintf("tcp://%s?bind=true", serverAddr))
	if err := waitForTCP(serverAddr, 2*time.Second); err != nil {
		t.Fatalf("Reverse server not ready: %v", err)
	}

	remotePort := getFreePort(t)
	go reverse.StartClient(fmt.Sprintf("tcp://:%d//%s", remotePort, targetAddr), fmt.Sprintf("tcp://%s", serverAddr))
	time.Sleep(500 * time.Millisecond)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort))
	if err != nil {
		t.Fatalf("Failed to connect to reverse exposed port: %v", err)
	}
	defer conn.Close()

	msg := "hello reverse"
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte(msg))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Failed to read echo: %v", err)
	}

	if string(buf) != msg {
		t.Errorf("Expected %q, got %q", msg, string(buf))
	}
}

func TestReverseQUIC(t *testing.T) {
	targetAddr, stopTarget := startMockTCPServer(t)
	defer stopTarget()

	orig := utils.GetInsecure()
	defer utils.SetInsecure(orig)
	utils.SetInsecure(true)

	serverAddr := fmt.Sprintf("127.0.0.1:%d", getFreePort(t))
	go reverse.StartServer(fmt.Sprintf("quic://%s?bind=true", serverAddr))
	time.Sleep(400 * time.Millisecond)

	remotePort := getFreePort(t)
	go reverse.StartClient(fmt.Sprintf("tcp://:%d//%s", remotePort, targetAddr), fmt.Sprintf("quic://%s", serverAddr))
	time.Sleep(700 * time.Millisecond)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort))
	if err != nil {
		t.Fatalf("Failed to connect to reverse exposed port: %v", err)
	}
	defer conn.Close()

	msg := "hello reverse quic"
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte(msg))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Failed to read echo: %v", err)
	}

	if string(buf) != msg {
		t.Errorf("Expected %q, got %q", msg, string(buf))
	}
}

func TestReverseStress(t *testing.T) {
	targetAddr, stopTarget := startMockTCPServer(t)
	defer stopTarget()

	serverAddr := fmt.Sprintf("127.0.0.1:%d", getFreePort(t))
	go reverse.StartServer(fmt.Sprintf("tcp://%s?bind=true", serverAddr))
	if err := waitForTCP(serverAddr, 2*time.Second); err != nil {
		t.Fatalf("Reverse server not ready: %v", err)
	}

	remotePort := getFreePort(t)
	go reverse.StartClient(fmt.Sprintf("tcp://:%d//%s", remotePort, targetAddr), fmt.Sprintf("tcp://%s", serverAddr))
	time.Sleep(500 * time.Millisecond)

	var wg sync.WaitGroup
	count := 30
	wg.Add(count)

	for i := 0; i < count; i++ {
		go func(id int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort))
			if err != nil {
				t.Errorf("Routine %d: Failed to connect: %v", id, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("stress %d", id)
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			conn.Write([]byte(msg))
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
