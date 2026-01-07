package tests

import (
	"bytes"
	"testing"

	socks5util "forward/internal/utils/socks5"
)

func TestEncodeAddrIPv4(t *testing.T) {
	addr, err := socks5util.EncodeAddr("192.168.1.1", 8080)
	if err != nil {
		t.Fatalf("EncodeAddr failed: %v", err)
	}

	// IPv4: atyp(1) + ip(4) + port(2) = 7 bytes
	if len(addr) != 7 {
		t.Errorf("encoded length = %d, want 7", len(addr))
	}
	if addr[0] != socks5util.AtypIPv4 {
		t.Errorf("atyp = 0x%02x, want 0x%02x", addr[0], socks5util.AtypIPv4)
	}
}

func TestEncodeAddrIPv6(t *testing.T) {
	addr, err := socks5util.EncodeAddr("::1", 443)
	if err != nil {
		t.Fatalf("EncodeAddr failed: %v", err)
	}

	// IPv6: atyp(1) + ip(16) + port(2) = 19 bytes
	if len(addr) != 19 {
		t.Errorf("encoded length = %d, want 19", len(addr))
	}
	if addr[0] != socks5util.AtypIPv6 {
		t.Errorf("atyp = 0x%02x, want 0x%02x", addr[0], socks5util.AtypIPv6)
	}
}

func TestEncodeAddrDomain(t *testing.T) {
	addr, err := socks5util.EncodeAddr("example.com", 80)
	if err != nil {
		t.Fatalf("EncodeAddr failed: %v", err)
	}

	// Domain: atyp(1) + len(1) + domain(11) + port(2) = 15 bytes
	if len(addr) != 15 {
		t.Errorf("encoded length = %d, want 15", len(addr))
	}
	if addr[0] != socks5util.AtypDomain {
		t.Errorf("atyp = 0x%02x, want 0x%02x", addr[0], socks5util.AtypDomain)
	}
	if addr[1] != 11 {
		t.Errorf("domain length = %d, want 11", addr[1])
	}
}

func TestEncodeAddrInvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"negative", -1},
		{"too large", 65536},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := socks5util.EncodeAddr("localhost", tt.port)
			if err == nil {
				t.Error("expected error for invalid port")
			}
		})
	}
}

func TestReadAddrIPv4(t *testing.T) {
	// 构造 IPv4 地址: 192.168.1.1:8080
	data := []byte{192, 168, 1, 1, 0x1f, 0x90} // 0x1f90 = 8080
	r := bytes.NewReader(data)

	host, port, err := socks5util.ReadAddr(r, socks5util.AtypIPv4)
	if err != nil {
		t.Fatalf("ReadAddr failed: %v", err)
	}
	if host != "192.168.1.1" {
		t.Errorf("host = %q, want %q", host, "192.168.1.1")
	}
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}
}

func TestReadAddrDomain(t *testing.T) {
	// 构造域名地址: example.com:443
	domain := "example.com"
	data := make([]byte, 0, 1+len(domain)+2)
	data = append(data, byte(len(domain)))
	data = append(data, []byte(domain)...)
	data = append(data, 0x01, 0xbb) // 0x01bb = 443

	r := bytes.NewReader(data)
	host, port, err := socks5util.ReadAddr(r, socks5util.AtypDomain)
	if err != nil {
		t.Fatalf("ReadAddr failed: %v", err)
	}
	if host != domain {
		t.Errorf("host = %q, want %q", host, domain)
	}
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
}

func TestContains(t *testing.T) {
	arr := []byte{0x00, 0x01, 0x02}

	tests := []struct {
		val  byte
		want bool
	}{
		{0x00, true},
		{0x01, true},
		{0x02, true},
		{0x03, false},
		{0xff, false},
	}

	for _, tt := range tests {
		if got := socks5util.Contains(arr, tt.val); got != tt.want {
			t.Errorf("Contains(%v, 0x%02x) = %v, want %v", arr, tt.val, got, tt.want)
		}
	}
}
