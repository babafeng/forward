package tests

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"forward/inner/config"
	"forward/inner/dialer"
	handlerTCP "forward/inner/handler/tcp"
	"forward/base/logging"
)

func TestTCPHandlerForward(t *testing.T) {
	// 启动目标服务器
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target server: %v", err)
	}
	defer targetLn.Close()

	// 目标服务器 echo
	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	cfg := config.Config{
		DialTimeout:   5 * time.Second,
		DialKeepAlive: 30 * time.Second,
		Logger:        logging.New(logging.Options{Level: logging.LevelOff}),
	}
	cfg.Forward = parseEndpoint(t, "tcp://"+targetLn.Addr().String())

	d := dialer.NewDirect(cfg)
	h := handlerTCP.New(cfg, d)

	// 创建客户端连接
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go h.Handle(ctx, serverConn)

	// 发送数据并验证回显
	testData := []byte("hello, tcp handler!")
	_, err = clientConn.Write(testData)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, len(testData))
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read failed: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf[:n], testData)
	}
}
