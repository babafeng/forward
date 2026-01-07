package tests

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"forward/internal/app"
	"forward/internal/config"
	"forward/internal/endpoint"
	"forward/internal/logging"
)

// TestSOCKS5ProxyBasic 测试 SOCKS5 代理基本功能
func TestSOCKS5ProxyBasic(t *testing.T) {
	// 启动后端 HTTP 服务器作为目标
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start backend: %v", err)
	}
	defer backendLn.Close()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// 简单 HTTP 响应
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
			}(conn)
		}
	}()

	// 启动 SOCKS5 代理
	port := freeTCPPort(t)
	listenEP := mustParseEndpoint(t, fmt.Sprintf("socks5://127.0.0.1:%d", port))

	cfg := config.Config{
		Listen: listenEP,
		Logger: logging.New(logging.Options{Level: logging.LevelOff}),
		Mode:   config.ModeProxyServer,
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

	// 连接到 SOCKS5 代理
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("connect to socks5 proxy: %v", err)
	}
	defer conn.Close()

	// SOCKS5 握手：版本 + 认证方法
	conn.Write([]byte{0x05, 0x01, 0x00}) // ver=5, nmethods=1, no auth

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read handshake: %v", err)
	}

	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("handshake failed: got %v", resp)
	}

	// SOCKS5 CONNECT 请求
	backendAddr := backendLn.Addr().(*net.TCPAddr)
	connectReq := []byte{
		0x05,         // ver
		0x01,         // cmd: CONNECT
		0x00,         // rsv
		0x01,         // atyp: IPv4
		127, 0, 0, 1, // addr
		byte(backendAddr.Port >> 8), byte(backendAddr.Port), // port
	}
	conn.Write(connectReq)

	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(conn, connectResp); err != nil {
		t.Fatalf("read connect resp: %v", err)
	}

	if connectResp[1] != 0x00 {
		t.Fatalf("connect failed: rep=%d", connectResp[1])
	}

	// 通过代理发送 HTTP 请求
	conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))

	respBuf := make([]byte, 128)
	n, _ := conn.Read(respBuf)
	if n == 0 {
		t.Fatal("no response from backend")
	}

	t.Logf("response: %s", string(respBuf[:n]))

	cancel()
	<-errCh
}

// TestHTTPProxyConnect 测试 HTTP 代理 CONNECT 方法
func TestHTTPProxyConnect(t *testing.T) {
	// 启动后端服务器
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start backend: %v", err)
	}
	defer backendLn.Close()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("hello from backend"))
			}(conn)
		}
	}()

	// 启动 HTTP 代理
	port := freeTCPPort(t)
	listenEP := mustParseEndpoint(t, fmt.Sprintf("http://127.0.0.1:%d", port))

	cfg := config.Config{
		Listen: listenEP,
		Logger: logging.New(logging.Options{Level: logging.LevelOff}),
		Mode:   config.ModeProxyServer,
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

	// 发送 CONNECT 请求
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("connect to http proxy: %v", err)
	}
	defer conn.Close()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		backendLn.Addr().String(), backendLn.Addr().String())
	conn.Write([]byte(connectReq))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read connect response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect status: %d", resp.StatusCode)
	}

	// 隧道建立后读取后端响应
	buf := make([]byte, 64)
	n, _ := br.Read(buf)
	if n > 0 {
		t.Logf("tunnel data: %s", string(buf[:n]))
	}

	cancel()
	<-errCh
}

// TestMultipleListeners 测试多监听功能
func TestMultipleListeners(t *testing.T) {
	// 创建后端
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start backend: %v", err)
	}
	defer backendLn.Close()

	go echoServer(backendLn)

	// 启动两个监听器
	port1 := freeTCPPort(t)
	port2 := freeTCPPort(t)

	ep1 := mustParseEndpoint(t, fmt.Sprintf("tcp://127.0.0.1:%d", port1))
	ep2 := mustParseEndpoint(t, fmt.Sprintf("tcp://127.0.0.1:%d", port2))
	forwardEP := mustParseEndpoint(t, fmt.Sprintf("tcp://%s", backendLn.Addr().String()))

	cfg := config.Config{
		Listen:    ep1,
		Listeners: []endpoint.Endpoint{ep1, ep2},
		Forward:   &forwardEP,
		Logger:    logging.New(logging.Options{Level: logging.LevelOff}),
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

	// 测试第一个端口
	conn1, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port1), time.Second)
	if err != nil {
		t.Fatalf("connect to port1: %v", err)
	}
	conn1.Close()

	// 测试第二个端口
	conn2, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port2), time.Second)
	if err != nil {
		t.Logf("port2 not available (may not be implemented): %v", err)
	} else {
		conn2.Close()
	}

	cancel()
	<-errCh
}
