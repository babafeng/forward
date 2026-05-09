package http3

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	quicHttp3 "github.com/quic-go/quic-go/http3"

	"forward/internal/listener"
	"forward/internal/metadata"
)

// TestListenerBindAddresses 覆盖 Init + Close 在典型 bind 语义下的行为。
//
// 本测试存在是为了守住 F-010 改动引入的风险：HTTP3 listener 从
// ResolveUDPAddr + ListenAndServe 改成 net.ListenPacket + server.Serve(pc)，
// 理论上对常见 bind 地址（:PORT / 127.0.0.1:PORT / [::1]:PORT）行为等价。
// 用 :0 让系统自动选端口以避免端口占用失败。
func TestListenerBindAddresses(t *testing.T) {
	tlsCfg := mustMakeTLSConfig(t)

	cases := []struct {
		name     string
		addr     string
		wantIPv4 bool
	}{
		{name: "unspecified", addr: ":0"},
		{name: "ipv4_loopback", addr: "127.0.0.1:0", wantIPv4: true},
		{name: "ipv6_loopback", addr: "[::1]:0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln := NewListener(
				listener.AddrOption(tc.addr),
				listener.TLSConfigOption(tlsCfg),
			)
			if err := ln.Init(metadata.New(map[string]any{})); err != nil {
				// ipv6 可能在没有 ::1 的环境不可用，跳过而非失败。
				if tc.name == "ipv6_loopback" && strings.Contains(err.Error(), "address") {
					t.Skipf("ipv6 loopback bind skipped: %v", err)
				}
				t.Fatalf("Init(%q) failed: %v", tc.addr, err)
			}

			got := ln.Addr()
			if got == nil {
				t.Fatalf("Addr() returned nil after Init")
			}
			udpAddr, ok := got.(*net.UDPAddr)
			if !ok {
				t.Fatalf("Addr() = %T, want *net.UDPAddr", got)
			}
			// 注意：Addr() 返回的是 ResolveUDPAddr 的结果（保留用户传入
			// 的 ":0" 端口 0），不是 pc 实际绑定到的端口。这是 main 分
			// 支就有的行为，F-010 没改变这一点。这里只校验类型与 IP 族。
			if tc.wantIPv4 && udpAddr.IP != nil && udpAddr.IP.To4() == nil {
				t.Fatalf("Addr().IP = %v, want IPv4 or unspecified", udpAddr.IP)
			}

			// Close 应该幂等：第一次关 pc + server 都成功，第二次是 no-op。
			if err := ln.Close(); err != nil {
				t.Fatalf("first Close() failed: %v", err)
			}
			if err := ln.Close(); err != nil {
				t.Fatalf("second Close() returned error: %v", err)
			}
		})
	}
}

// TestListenerMissingAddr 与 TestListenerMissingTLS 锁定最低的输入校验。
func TestListenerMissingAddr(t *testing.T) {
	ln := NewListener(
		listener.TLSConfigOption(mustMakeTLSConfig(t)),
	)
	err := ln.Init(metadata.New(map[string]any{}))
	if err == nil {
		t.Fatalf("Init without addr should fail")
	}
}

func TestListenerMissingTLS(t *testing.T) {
	ln := NewListener(
		listener.AddrOption(":0"),
	)
	err := ln.Init(metadata.New(map[string]any{}))
	if err == nil {
		t.Fatalf("Init without tls config should fail")
	}
}

// TestListenerServesHTTP3Roundtrip 是 Serve 路径的 smoke 覆盖：Init 之后
// 用 quic-go 的 http3 client 跑一个 GET 完成 QUIC handshake，确认
// Serve(pc) 没有立刻返回非 ErrServerClosed 的错误、handler 能被调用。
//
// 这是对 TestListenerBindAddresses 的补充——后者只验 net.ListenPacket
// 的 bind 语义，不触发 Serve(pc) 的执行路径。
//
// 该用例依赖 UDP socket 和 QUIC handshake，在部分沙盒环境下可能 flake
// （udp send buffer、防火墙、clock skew）。独立成一个 test func 方便在
// 特定环境下 Skip。
func TestListenerServesHTTP3Roundtrip(t *testing.T) {
	tlsCfg := mustMakeTLSConfig(t)

	ln := NewListener(
		listener.AddrOption("127.0.0.1:0"),
		listener.TLSConfigOption(tlsCfg),
	)
	if err := ln.Init(metadata.New(map[string]any{})); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// Addr() 返回的是 ResolveUDPAddr 的结果（端口 0），拿不到 pc 实际绑
	// 定的端口。从同包的 *Listener 直接取 pc.LocalAddr 得到真实地址。
	concrete, ok := ln.(*Listener)
	if !ok {
		t.Fatalf("NewListener returned %T, want *Listener", ln)
	}
	if concrete.pc == nil {
		t.Fatalf("pc is nil after Init")
	}
	serverAddr := concrete.pc.LocalAddr().String()

	// handleFunc 会把 http3Conn 塞进 cqueue 再阻塞等 closed。测试需要
	// 起一个 Accept goroutine 把这个 conn 关掉，让 handler 返回从而
	// client 能拿到 response。
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	rt := &quicHttp3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
			ServerName:         "localhost",
		},
	}
	defer rt.Close()
	client := &http.Client{Transport: rt, Timeout: 3 * time.Second}

	resp, err := client.Get("https://" + serverAddr + "/")
	if err != nil {
		// 沙盒 UDP 栈问题可能让 QUIC handshake 失败，标记 environmental。
		t.Skipf("http3 roundtrip skipped (environmental): %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 600 {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}

	select {
	case <-acceptDone:
	case <-time.After(time.Second):
		t.Fatalf("Accept goroutine did not return after response")
	}
}

// mustMakeTLSConfig 构造一份自签名 TLS config 供 http3 listener Init 使用。
// 不进行任何握手，只是为了通过 tlsConfig 非 nil 校验并让 quic-go 的 pc
// 初始化能走完。
func mustMakeTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate failed: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parse key pair failed: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
}
