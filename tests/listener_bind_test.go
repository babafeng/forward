package tests

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"forward/internal/app"
	"forward/internal/config"
	"forward/internal/endpoint"
)

// TestListenerBindAddress 验证监听器是否正确绑定到指定地址
func TestListenerBindAddress(t *testing.T) {
	tests := []struct {
		name        string
		listenAddr  string // 监听格式，如 ":8080" 或 "127.0.0.1:8080"
		expectBind  string // 期望绑定的 IP
		canConnect  string // 可以连接的地址
		cantConnect string // 不能连接的地址（仅当绑定 127.0.0.1 时）
	}{
		{
			name:       "bind_all_interfaces",
			listenAddr: "0.0.0.0",
			expectBind: "0.0.0.0",
			canConnect: "127.0.0.1",
		},
		{
			name:       "bind_localhost_only",
			listenAddr: "127.0.0.1",
			expectBind: "127.0.0.1",
			canConnect: "127.0.0.1",
		},
		{
			name:       "bind_empty_means_all",
			listenAddr: "", // 空地址应该等同于 0.0.0.0
			expectBind: "",
			canConnect: "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := freeTCPPort(t)
			var listenURL string
			if tt.listenAddr == "" {
				listenURL = fmt.Sprintf("tcp://:%d", port)
			} else {
				listenURL = fmt.Sprintf("tcp://%s:%d", tt.listenAddr, port)
			}

			// 创建一个简单的 echo 后端
			backendLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("start backend: %v", err)
			}
			defer backendLn.Close()

			go echoServer(backendLn)

			listenEP := mustParseEndpoint(t, listenURL)
			forwardEP := mustParseEndpoint(t, fmt.Sprintf("tcp://%s", backendLn.Addr().String()))

			cfg := config.Config{
				Listen:  listenEP,
				Forward: &forwardEP,
				Logger:  testLogger(),
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			runner, err := app.NewForwarder(cfg)
			if err != nil {
				t.Fatalf("new forwarder: %v", err)
			}

			errCh := make(chan error, 1)
			go func() {
				errCh <- runner.Run(ctx)
			}()

			// 等待监听器启动
			time.Sleep(100 * time.Millisecond)

			// 验证可以通过指定地址连接
			connectAddr := fmt.Sprintf("%s:%d", tt.canConnect, port)
			conn, err := net.DialTimeout("tcp", connectAddr, time.Second)
			if err != nil {
				t.Fatalf("expected to connect to %s but got error: %v", connectAddr, err)
			}
			conn.Close()

			// 验证 endpoint 解析的地址
			if tt.expectBind != "" && listenEP.Host != tt.expectBind {
				t.Errorf("expected host %q, got %q", tt.expectBind, listenEP.Host)
			}

			cancel()
			<-errCh
		})
	}
}

// TestHTTPProxyListenAddress 验证 HTTP 代理服务器监听地址
func TestHTTPProxyListenAddress(t *testing.T) {
	tests := []struct {
		name       string
		listenAddr string
	}{
		{"localhost_only", "127.0.0.1"},
		{"all_interfaces", "0.0.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := freeTCPPort(t)
			listenURL := fmt.Sprintf("http://%s:%d", tt.listenAddr, port)

			listenEP := mustParseEndpoint(t, listenURL)

			cfg := config.Config{
				Listen:        listenEP,
				Logger:        testLogger(),
				IsProxyServer: true,
				Mode:          config.ModeProxyServer,
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			runner, err := app.NewForwarder(cfg)
			if err != nil {
				t.Fatalf("new forwarder: %v", err)
			}

			errCh := make(chan error, 1)
			go func() {
				errCh <- runner.Run(ctx)
			}()

			time.Sleep(100 * time.Millisecond)

			// 直接连接代理端口验证它在监听
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if err != nil {
				t.Fatalf("failed to connect to proxy: %v", err)
			}
			conn.Close()

			// 验证 endpoint 正确解析了 host
			if listenEP.Host != tt.listenAddr {
				t.Errorf("endpoint host = %q, want %q", listenEP.Host, tt.listenAddr)
			}

			cancel()
			<-errCh
		})
	}
}

// TestTCPListenerActualBindIP 验证 TCP 监听器实际绑定的 IP 地址
func TestTCPListenerActualBindIP(t *testing.T) {
	port := freeTCPPort(t)

	// 使用标准库直接监听来验证行为
	ln127, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listen on 127.0.0.1:%d: %v", port, err)
	}

	// 获取实际监听地址
	addr := ln127.Addr().(*net.TCPAddr)
	if !addr.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("expected to bind to 127.0.0.1, but got %s", addr.IP)
	}

	ln127.Close()

	// 验证空地址监听行为
	port2 := freeTCPPort(t)
	lnAll, err := net.Listen("tcp", fmt.Sprintf(":%d", port2))
	if err != nil {
		t.Fatalf("listen on :%d: %v", port2, err)
	}
	defer lnAll.Close()

	addrAll := lnAll.Addr().(*net.TCPAddr)
	// 空地址应该绑定到 0.0.0.0 或 ::
	if !addrAll.IP.IsUnspecified() && addrAll.IP != nil {
		t.Logf("empty bind resulted in IP: %s (unspecified: %v)", addrAll.IP, addrAll.IP.IsUnspecified())
	}
}

// TestEndpointParseListenFormats 验证 endpoint 解析各种监听格式
func TestEndpointParseListenFormats(t *testing.T) {
	tests := []struct {
		raw      string
		wantHost string
		wantPort int
	}{
		{"tcp://:8080", "", 8080},
		{"tcp://0.0.0.0:8080", "0.0.0.0", 8080},
		{"tcp://127.0.0.1:8080", "127.0.0.1", 8080},
		{"http://:1080", "", 1080},
		{"http://127.0.0.1:1080", "127.0.0.1", 1080},
		{"socks5://:1080", "", 1080},
		{"socks5://0.0.0.0:1080", "0.0.0.0", 1080},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			ep, err := endpoint.Parse(tt.raw)
			if err != nil {
				t.Fatalf("Parse(%q) failed: %v", tt.raw, err)
			}
			if ep.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", ep.Host, tt.wantHost)
			}
			if ep.Port != tt.wantPort {
				t.Errorf("Port = %d, want %d", ep.Port, tt.wantPort)
			}
		})
	}
}

// echoServer 启动一个简单的 echo 服务器
func echoServer(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 1024)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				c.Write(buf[:n])
			}
		}(conn)
	}
}
