package tests

import (
	"fmt"
	"io"
	"testing"
	"time"

	"go-forward/core/proxy"
	"go-forward/core/utils"
)

func TestProxyProtocols(t *testing.T) {
	targetAddr, stopTarget := startMockTCPServer(t)
	defer stopTarget()

	cases := []struct {
		name   string
		scheme string
	}{
		{name: "http", scheme: "http"},
		{name: "https", scheme: "https"},
		{name: "http2", scheme: "http2"},
		{name: "http3", scheme: "http3"},
		{name: "quic", scheme: "quic"},
		{name: "ssh", scheme: "ssh"},
		{name: "tls", scheme: "tls"},
		{name: "socks5", scheme: "socks5"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name+"/no-auth", func(t *testing.T) {
			runProxyCase(t, tc.scheme, false, targetAddr)
		})
		t.Run(tc.name+"/auth", func(t *testing.T) {
			runProxyCase(t, tc.scheme, true, targetAddr)
		})
	}
}

func runProxyCase(t *testing.T, scheme string, withAuth bool, targetAddr string) {
	t.Helper()

	addr := fmt.Sprintf("127.0.0.1:%d", getFreePort(t))
	user := "user"
	pass := "pass"

	listenURL := fmt.Sprintf("%s://%s", scheme, addr)
	forwardURL := listenURL
	if withAuth {
		listenURL = fmt.Sprintf("%s://%s:%s@%s", scheme, user, pass, addr)
		forwardURL = listenURL
	}
	if scheme == "ssh" && !withAuth {
		// Provide an empty password to avoid "none" auth.
		forwardURL = fmt.Sprintf("%s://%s:@%s", scheme, user, addr)
	}

	go proxy.Start(listenURL, "")
	waitForProxyStart(t, scheme, addr)

	origInsecure := utils.GetInsecure()
	defer utils.SetInsecure(origInsecure)
	if scheme == "https" || scheme == "http2" || scheme == "http3" || scheme == "quic" || scheme == "tls" || scheme == "ssh" {
		utils.SetInsecure(true)
	}

	conn, err := proxy.Dial("tcp", targetAddr, forwardURL)
	if err != nil {
		t.Fatalf("Proxy dial failed for %s (auth=%v): %v", scheme, withAuth, err)
	}
	defer conn.Close()

	msg := fmt.Sprintf("hello-%s-%v", scheme, withAuth)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("Expected %q, got %q", msg, string(buf))
	}
}

func waitForProxyStart(t *testing.T, scheme, addr string) {
	t.Helper()
	if scheme == "quic" || scheme == "http3" {
		time.Sleep(400 * time.Millisecond)
		return
	}
	if err := waitForTCP(addr, 2*time.Second); err != nil {
		t.Fatalf("Proxy %s failed to start on %s: %v", scheme, addr, err)
	}
}

func TestProxyInsecureToggle(t *testing.T) {
	targetAddr, stopTarget := startMockTCPServer(t)
	defer stopTarget()

	cases := []struct {
		name   string
		scheme string
	}{
		{name: "tls", scheme: "tls"},
		{name: "https", scheme: "https"},
		{name: "http2", scheme: "http2"},
		{name: "http3", scheme: "http3"},
		{name: "quic", scheme: "quic"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			addr := fmt.Sprintf("127.0.0.1:%d", getFreePort(t))
			listenURL := fmt.Sprintf("%s://%s", tc.scheme, addr)

			go proxy.Start(listenURL, "")
			waitForProxyStart(t, tc.scheme, addr)

			origInsecure := utils.GetInsecure()
			defer utils.SetInsecure(origInsecure)

			utils.SetInsecure(false)
			if conn, err := proxy.Dial("tcp", targetAddr, listenURL); err == nil {
				conn.Close()
				t.Fatalf("Expected failure with insecure=false for %s", tc.scheme)
			}

			utils.SetInsecure(true)
			conn, err := proxy.Dial("tcp", targetAddr, listenURL)
			if err != nil {
				t.Fatalf("Expected success with insecure=true for %s: %v", tc.scheme, err)
			}
			defer conn.Close()

			msg := "insecure-ok"
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write([]byte(msg)); err != nil {
				t.Fatalf("Write failed: %v", err)
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatalf("Read failed: %v", err)
			}
			if string(buf) != msg {
				t.Fatalf("Expected %q, got %q", msg, string(buf))
			}
		})
	}
}

func TestProxyStress(t *testing.T) {
	targetAddr, stopTarget := startMockTCPServer(t)
	defer stopTarget()

	addr := fmt.Sprintf("127.0.0.1:%d", getFreePort(t))
	listenURL := fmt.Sprintf("socks5://%s", addr)
	go proxy.Start(listenURL, "")
	waitForProxyStart(t, "socks5", addr)

	count := 30
	errCh := make(chan error, count)
	for i := 0; i < count; i++ {
		go func(id int) {
			conn, err := proxy.Dial("tcp", targetAddr, listenURL)
			if err != nil {
				errCh <- fmt.Errorf("dial %d: %v", id, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("stress-%d", id)
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write([]byte(msg)); err != nil {
				errCh <- fmt.Errorf("write %d: %v", id, err)
				return
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil {
				errCh <- fmt.Errorf("read %d: %v", id, err)
				return
			}
			if string(buf) != msg {
				errCh <- fmt.Errorf("mismatch %d", id)
				return
			}
			errCh <- nil
		}(i)
	}

	for i := 0; i < count; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}
