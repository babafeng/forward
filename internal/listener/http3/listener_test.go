package http3

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

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
