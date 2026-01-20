package tests

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"forward/inner/app"
	"forward/inner/auth"
	"forward/inner/config"
	"forward/base/logging"
)

// TestSOCKS5WithAuth 测试带认证的 SOCKS5 代理
func TestSOCKS5WithAuth(t *testing.T) {
	// 启动后端
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
				c.Write([]byte("authenticated!"))
			}(conn)
		}
	}()

	// 启动带认证的 SOCKS5 代理
	port := freeTCPPort(t)
	listenEP := mustParseEndpoint(t, fmt.Sprintf("socks5://testuser:testpass@127.0.0.1:%d", port))

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

	// 连接代理
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	// SOCKS5 握手：支持用户名密码认证
	conn.Write([]byte{0x05, 0x01, 0x02}) // ver=5, nmethods=1, user/pass

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read handshake: %v", err)
	}

	if resp[0] != 0x05 || resp[1] != 0x02 {
		t.Fatalf("expected user/pass auth, got %v", resp)
	}

	// 发送认证信息
	user := "testuser"
	pass := "testpass"
	authReq := []byte{0x01, byte(len(user))}
	authReq = append(authReq, []byte(user)...)
	authReq = append(authReq, byte(len(pass)))
	authReq = append(authReq, []byte(pass)...)
	conn.Write(authReq)

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatalf("read auth resp: %v", err)
	}

	if authResp[1] != 0x00 {
		t.Fatalf("auth failed: %v", authResp)
	}

	t.Log("SOCKS5 authentication successful")

	conn.Close()
	cancel()
	<-errCh
}

// TestSOCKS5AuthFail 测试错误密码认证失败
func TestSOCKS5AuthFail(t *testing.T) {
	port := freeTCPPort(t)
	listenEP := mustParseEndpoint(t, fmt.Sprintf("socks5://admin:secret@127.0.0.1:%d", port))

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

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	// 握手
	conn.Write([]byte{0x05, 0x01, 0x02})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)

	// 发送错误密码
	user := "admin"
	pass := "wrongpass"
	authReq := []byte{0x01, byte(len(user))}
	authReq = append(authReq, []byte(user)...)
	authReq = append(authReq, byte(len(pass)))
	authReq = append(authReq, []byte(pass)...)
	conn.Write(authReq)

	authResp := make([]byte, 2)
	n, _ := io.ReadFull(conn, authResp)
	if n > 0 && authResp[1] == 0x00 {
		t.Error("expected auth to fail with wrong password")
	} else {
		t.Log("auth correctly rejected wrong password")
	}

	cancel()
	<-errCh
}

// TestAuthenticatorInterface 测试认证器接口
func TestAuthenticatorInterface(t *testing.T) {
	a := auth.FromUserPass("admin", "secret123")

	// 正确凭据
	if !a.Check("admin", "secret123") {
		t.Error("correct credentials should pass")
	}

	// 错误用户名
	if a.Check("wronguser", "secret123") {
		t.Error("wrong username should fail")
	}

	// 错误密码
	if a.Check("admin", "wrongpass") {
		t.Error("wrong password should fail")
	}

	// 空凭据
	if a.Check("", "") {
		t.Error("empty credentials should fail")
	}
}

// TestEndpointUserPass 测试从 endpoint 提取用户名密码
func TestEndpointUserPass(t *testing.T) {
	tests := []struct {
		raw      string
		wantUser string
		wantPass string
		wantOK   bool
	}{
		{"socks5://user:pass@127.0.0.1:1080", "user", "pass", true},
		{"http://admin:secret@:8080", "admin", "secret", true},
		{"tcp://127.0.0.1:8080", "", "", false},
		{"socks5://:1080", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			ep := mustParseEndpoint(t, tt.raw)
			user, pass, ok := ep.UserPass()

			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if user != tt.wantUser {
				t.Errorf("user = %q, want %q", user, tt.wantUser)
			}
			if pass != tt.wantPass {
				t.Errorf("pass = %q, want %q", pass, tt.wantPass)
			}
		})
	}
}
