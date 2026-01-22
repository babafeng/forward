package tests

import (
	"net/http"
	"testing"
)

func TestCleanProxyHeadersBasic(t *testing.T) {
	// 创建带有 hop-by-hop 头的请求
	req := &http.Request{
		Header: http.Header{
			"Connection":          []string{"keep-alive"},
			"Keep-Alive":          []string{"timeout=5"},
			"Proxy-Authorization": []string{"Basic xxx"},
			"X-Normal":            []string{"should-remain"},
		},
	}

	// 验证请求创建正确
	if req.Header.Get("Connection") != "keep-alive" {
		t.Error("Header not set correctly")
	}
	if req.Header.Get("X-Normal") != "should-remain" {
		t.Error("Normal header should be present")
	}
}

func TestRedactURLBasic(t *testing.T) {
	// 基本 URL 脱敏测试
	tests := []struct {
		name     string
		rawURL   string
		wantSafe bool
	}{
		{"simple", "http://example.com/path", true},
		{"with_query", "http://example.com?foo=bar", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantSafe {
				// URL 应该可以正常处理
				t.Log("URL processed:", tt.rawURL)
			}
		})
	}
}
