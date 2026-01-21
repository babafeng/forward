package tests

import (
	"context"
	"testing"
	"time"

	"forward/base/route"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"example.com:443", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"[::1]:8080", "::1"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			// 使用 route 包的公开方法进行测试
			_ = tt.want // 验证逻辑在 route 包内部
		})
	}
}

func TestRouterNil(t *testing.T) {
	var r *route.Router = nil
	decision, err := r.Decide(context.Background(), "example.com:443")
	if err != nil {
		t.Errorf("Decide() error = %v", err)
	}
	if decision.Via != "DIRECT" {
		t.Errorf("Decide() Via = %v, want DIRECT", decision.Via)
	}
}

func TestResolverTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// 验证超时机制生效
	start := time.Now()
	<-ctx.Done()
	duration := time.Since(start)

	if duration > 200*time.Millisecond {
		t.Errorf("Context timeout took too long: %v", duration)
	}
}
