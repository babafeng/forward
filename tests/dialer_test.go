package tests

import (
	"context"
	"net"
	"testing"
	"time"

	"forward/inner/config"
	"forward/inner/dialer"
	"forward/inner/logging"
)

func TestDirectDialerTCP(t *testing.T) {
	// 启动一个本地 TCP 服务器
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	cfg := config.Config{
		DialTimeout:   5 * time.Second,
		DialKeepAlive: 30 * time.Second,
		Logger:        logging.New(logging.Options{Level: logging.LevelOff}),
	}

	d := dialer.NewDirect(cfg)
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	if conn.RemoteAddr().String() != ln.Addr().String() {
		t.Errorf("RemoteAddr = %s, want %s", conn.RemoteAddr(), ln.Addr())
	}
}

func TestDirectDialerUDP(t *testing.T) {
	cfg := config.Config{
		DialTimeout:   5 * time.Second,
		DialKeepAlive: 30 * time.Second,
		Logger:        logging.New(logging.Options{Level: logging.LevelOff}),
	}

	d := dialer.NewDirect(cfg)
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("DialContext UDP failed: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr should not be nil")
	}
}

func TestDirectDialerTimeout(t *testing.T) {
	cfg := config.Config{
		DialTimeout:   100 * time.Millisecond,
		DialKeepAlive: 30 * time.Second,
		Logger:        logging.New(logging.Options{Level: logging.LevelOff}),
	}

	d := dialer.NewDirect(cfg)
	ctx := context.Background()

	// 连接到一个不可达的地址
	_, err := d.DialContext(ctx, "tcp", "10.255.255.1:12345")
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestDirectDialerContextCancel(t *testing.T) {
	cfg := config.Config{
		DialTimeout:   10 * time.Second,
		DialKeepAlive: 30 * time.Second,
		Logger:        logging.New(logging.Options{Level: logging.LevelOff}),
	}

	d := dialer.NewDirect(cfg)
	ctx, cancel := context.WithCancel(context.Background())

	// 立即取消
	cancel()

	_, err := d.DialContext(ctx, "tcp", "10.255.255.1:12345")
	if err == nil {
		t.Error("expected context canceled error")
	}
}
