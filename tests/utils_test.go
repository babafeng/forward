package tests

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"go-forward/core/utils"
)

func TestURLParseAndRedact(t *testing.T) {
	scheme, auth, addr := utils.URLParse("http://user:pass@127.0.0.1:8080?cert=/tmp/cert&key=/tmp/key")
	if scheme != "http" {
		t.Fatalf("expected scheme http, got %s", scheme)
	}
	if addr != "127.0.0.1:8080" {
		t.Fatalf("expected addr 127.0.0.1:8080, got %s", addr)
	}
	if auth == nil || auth.User != "user" || auth.Pass != "pass" {
		t.Fatalf("auth parsed incorrectly: %#v", auth)
	}
	redacted := utils.RedactURL("http://user:pass@127.0.0.1:8080")
	if redacted == "http://user:pass@127.0.0.1:8080" || redacted == "" {
		t.Fatalf("expected password redacted, got %s", redacted)
	}

	scheme, auth, addr = utils.URLParse("user:pass@:1080")
	if scheme != "" {
		t.Fatalf("expected empty scheme for sniffing, got %s", scheme)
	}
	if addr != ":1080" {
		t.Fatalf("expected addr :1080, got %s", addr)
	}
	if auth == nil || auth.User != "user" || auth.Pass != "pass" {
		t.Fatalf("auth parsed incorrectly for sniffing: %#v", auth)
	}
	redacted = utils.RedactURL("user:pass@:1080")
	if redacted == "" || strings.Contains(redacted, "pass") || strings.Contains(redacted, "auto://") {
		t.Fatalf("expected password redacted for sniffing, got %s", redacted)
	}

	scheme, auth, addr = utils.URLParse("user:pass@127.0.0.1:1080")
	if scheme != "" {
		t.Fatalf("expected empty scheme for sniffing host:port, got %s", scheme)
	}
	if addr != "127.0.0.1:1080" {
		t.Fatalf("expected addr 127.0.0.1:1080, got %s", addr)
	}
	if auth == nil || auth.User != "user" || auth.Pass != "pass" {
		t.Fatalf("auth parsed incorrectly for sniffing host:port: %#v", auth)
	}
	redacted = utils.RedactURL("user:pass@127.0.0.1:1080")
	if redacted == "" || strings.Contains(redacted, "pass") || strings.Contains(redacted, "auto://") {
		t.Fatalf("expected password redacted for sniffing host:port, got %s", redacted)
	}
}

func TestParseURLParams(t *testing.T) {
	params := utils.ParseURLParams("http://example.com:443?cert=/tmp/cert&key=/tmp/key")
	if params == nil {
		t.Fatalf("expected params")
	}
	if params.Get("cert") != "/tmp/cert" || params.Get("key") != "/tmp/key" {
		t.Fatalf("unexpected params: %v", params)
	}
}

func TestIsValidHostPort(t *testing.T) {
	cases := []struct {
		in     string
		expect bool
	}{
		{"127.0.0.1:80", true},
		{"::1:443", false},
		{"[::1]:443", true},
		{"example.com:8080", true},
		{"bad_host:65536", false},
		{"noport", false},
	}
	for _, tc := range cases {
		if got := utils.IsValidHostPort(tc.in); got != tc.expect {
			t.Fatalf("IsValidHostPort(%s) = %v, want %v", tc.in, got, tc.expect)
		}
	}
}

func TestFixURLScheme(t *testing.T) {
	if got := utils.FixURLScheme("http2://host:443"); got != "https://host:443" {
		t.Fatalf("FixURLScheme failed, got %s", got)
	}
	if got := utils.FixURLScheme("socks5://host:1080"); got != "socks5://host:1080" {
		t.Fatalf("FixURLScheme should not change other schemes")
	}
}

func TestSocks5AddrRoundTrip(t *testing.T) {
	addr := "example.com:443"
	buf := &bytes.Buffer{}
	if err := utils.WriteSocks5Addr(buf, addr); err != nil {
		t.Fatalf("WriteSocks5Addr error: %v", err)
	}
	data := buf.Bytes()
	atyp := data[0]
	parsed, err := utils.ReadSocks5Addr(bytes.NewReader(data[1:]), atyp)
	if err != nil {
		t.Fatalf("ReadSocks5Addr error: %v", err)
	}
	if parsed != addr {
		t.Fatalf("expected %s, got %s", addr, parsed)
	}
}

func TestAuthValidate(t *testing.T) {
	auth, err := utils.NewAuth("user:pass")
	if err != nil {
		t.Fatalf("NewAuth error: %v", err)
	}
	if !auth.Validate("user", "pass") {
		t.Fatalf("expected credentials to validate")
	}
	if auth.Validate("user", "bad") {
		t.Fatalf("expected invalid password to fail validation")
	}
}

func TestGetSocks5ReplyCode(t *testing.T) {
	cases := []struct {
		err  error
		want byte
	}{
		{errors.New("connection refused"), 0x05},
		{errors.New("network is unreachable"), 0x03},
		{errors.New("i/o timeout"), 0x04},
		{fmt.Errorf("unknown error"), 0x01},
	}
	for _, tc := range cases {
		if got := utils.GetSocks5ReplyCode(tc.err); got != tc.want {
			t.Fatalf("GetSocks5ReplyCode(%v) = 0x%02x, want 0x%02x", tc.err, got, tc.want)
		}
	}
}
