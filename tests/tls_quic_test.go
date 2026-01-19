package tests

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"forward/inner/config"
	tlsconfig "forward/inner/config/tls"
	"forward/inner/endpoint"
	"forward/inner/logging"
)

// TestTLSServerConfigGenerate 测试 TLS 服务端配置生成
func TestTLSServerConfigGenerate(t *testing.T) {
	ep := mustParseEndpoint(t, "tls://127.0.0.1:2333")

	cfg := config.Config{
		Listen: ep,
		Logger: logging.New(logging.Options{Level: logging.LevelOff}),
	}

	serverCfg, err := tlsconfig.ServerConfig(cfg, tlsconfig.ServerOptions{})
	if err != nil {
		t.Fatalf("ServerConfig failed: %v", err)
	}

	if serverCfg == nil {
		t.Fatal("ServerConfig returned nil")
	}

	if len(serverCfg.Certificates) == 0 {
		t.Error("no certificates generated")
	}
}

// TestTLSClientConfig 测试客户端 TLS 配置
func TestTLSClientConfig(t *testing.T) {
	ep := mustParseEndpoint(t, "tls://example.com:443")

	clientCfg, err := tlsconfig.ClientConfig(ep, false, tlsconfig.ClientOptions{})
	if err != nil {
		t.Fatalf("ClientConfig failed: %v", err)
	}

	if clientCfg == nil {
		t.Fatal("ClientConfig returned nil")
	}

	// 验证 ServerName
	if clientCfg.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", clientCfg.ServerName, "example.com")
	}
}

// TestTLSClientConfigInsecure 测试跳过证书验证
func TestTLSClientConfigInsecure(t *testing.T) {
	ep := mustParseEndpoint(t, "tls://example.com:443")

	clientCfg, err := tlsconfig.ClientConfig(ep, true, tlsconfig.ClientOptions{})
	if err != nil {
		t.Fatalf("ClientConfig failed: %v", err)
	}

	if !clientCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

// TestTLSListenerConnection 测试 TLS 监听器连接
func TestTLSListenerConnection(t *testing.T) {
	port := freeTCPPort2(t)
	ep := mustParseEndpoint(t, fmt.Sprintf("tls://127.0.0.1:%d", port))

	cfg := config.Config{
		Listen: ep,
		Logger: logging.New(logging.Options{Level: logging.LevelOff}),
	}

	serverCfg, err := tlsconfig.ServerConfig(cfg, tlsconfig.ServerOptions{})
	if err != nil {
		t.Fatalf("ServerConfig failed: %v", err)
	}

	// 启动 TLS 监听器
	ln, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port), serverCfg)
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("hello tls"))
	}()

	// 客户端连接
	addr := ln.Addr().String()
	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("tls.Dial failed: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(buf[:n]) != "hello tls" {
		t.Errorf("unexpected response: %q", string(buf[:n]))
	}
}

// TestEndpointWithTLSOptions 测试带 TLS 选项的 endpoint 解析
func TestEndpointWithTLSOptions(t *testing.T) {
	tests := []struct {
		raw      string
		wantCert bool
		wantKey  bool
		wantCA   bool
		wantBind bool
	}{
		{
			raw:      "tls://127.0.0.1:2333",
			wantCert: false,
		},
		{
			raw:      "tls://127.0.0.1:2333?cert=/path/cert.pem&key=/path/key.pem",
			wantCert: true,
			wantKey:  true,
		},
		{
			raw:    "tls://127.0.0.1:2333?ca=/path/ca.pem",
			wantCA: true,
		},
		{
			raw:      "tls://127.0.0.1:2333?bind=true",
			wantBind: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			ep, err := endpoint.Parse(tt.raw)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			cert := ep.Query.Get("cert")
			key := ep.Query.Get("key")
			ca := ep.Query.Get("ca")
			bind := ep.Query.Get("bind")

			if tt.wantCert && cert == "" {
				t.Error("expected cert option")
			}
			if tt.wantKey && key == "" {
				t.Error("expected key option")
			}
			if tt.wantCA && ca == "" {
				t.Error("expected ca option")
			}
			if tt.wantBind && bind != "true" {
				t.Errorf("bind = %q, want 'true'", bind)
			}
		})
	}
}

// TestQUICEndpointParse 测试 QUIC endpoint 解析
func TestQUICEndpointParse(t *testing.T) {
	tests := []struct {
		raw      string
		wantHost string
		wantPort int
	}{
		{"quic://127.0.0.1:2333", "127.0.0.1", 2333},
		{"quic://:2333", "", 2333},
		{"quic://0.0.0.0:443", "0.0.0.0", 443},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			ep, err := endpoint.Parse(tt.raw)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			if ep.Scheme != "quic" {
				t.Errorf("Scheme = %q, want 'quic'", ep.Scheme)
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

// TestHTTP3EndpointParse 测试 HTTP/3 endpoint 解析
func TestHTTP3EndpointParse(t *testing.T) {
	tests := []struct {
		raw      string
		wantHost string
		wantPort int
	}{
		{"http3://127.0.0.1:443", "127.0.0.1", 443},
		{"http3://:443", "", 443},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			ep, err := endpoint.Parse(tt.raw)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			if ep.Scheme != "http3" {
				t.Errorf("Scheme = %q, want 'http3'", ep.Scheme)
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

// TestHTTP2EndpointParse 测试 HTTP/2 endpoint 解析
func TestHTTP2EndpointParse(t *testing.T) {
	ep, err := endpoint.Parse("http2://127.0.0.1:443")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if ep.Scheme != "http2" {
		t.Errorf("Scheme = %q, want 'http2'", ep.Scheme)
	}
}

// 辅助函数
func freeTCPPort2(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
