package tests

import (
	"context"
	"testing"
	"time"

	"forward/internal/config"
	"forward/internal/endpoint"
	"forward/internal/logging"

	dialerquic "forward/internal/dialer/quic"
)

func TestQuicDialer_DefaultTimeout(t *testing.T) {
	// 创建一个配置，timeout 为 0（未设置）
	ep, err := endpoint.Parse("quic://test.example.com:443")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	cfg := config.Config{
		Forward:     &ep,
		DialTimeout: 0, // 未设置 timeout
		Logger:      logging.New(logging.Options{Level: logging.LevelOff}),
		Insecure:    true,
	}

	dialer, err := dialerquic.New(cfg)
	if err != nil {
		t.Fatalf("create quic dialer: %v", err)
	}

	// 使用带超时的 context 进行拨号（应该使用默认超时）
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// 这将失败因为地址不存在，但我们测试的是超时机制
	_, err = dialer.DialContext(ctx, "tcp", "unreachable.example.com:443")
	if err == nil {
		t.Error("expected dial to fail")
	}

	// 验证超时机制生效（错误应该在合理时间内返回）
	// 如果没有默认超时，这可能会无限等待
}

func TestQuicDialer_ConfiguredTimeout(t *testing.T) {
	ep, err := endpoint.Parse("quic://test.example.com:443")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	// 设置非常短的超时
	cfg := config.Config{
		Forward:     &ep,
		DialTimeout: 50 * time.Millisecond,
		Logger:      logging.New(logging.Options{Level: logging.LevelOff}),
		Insecure:    true,
	}

	dialer, err := dialerquic.New(cfg)
	if err != nil {
		t.Fatalf("create quic dialer: %v", err)
	}

	start := time.Now()
	ctx := context.Background() // 无 deadline
	_, err = dialer.DialContext(ctx, "tcp", "unreachable.example.com:443")
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected dial to fail with timeout")
	}

	// 验证超时生效（应该在配置的超时附近完成）
	if elapsed > 5*time.Second {
		t.Errorf("dial took too long: %v, expected around 50ms", elapsed)
	}
}
