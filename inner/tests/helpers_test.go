package tests

import (
	"testing"

	"forward/base/endpoint"
)

// parseEndpoint 是测试辅助函数，解析 endpoint 并处理错误
func parseEndpoint(t *testing.T, raw string) *endpoint.Endpoint {
	t.Helper()
	ep, err := endpoint.Parse(raw)
	if err != nil {
		t.Fatalf("failed to parse endpoint %q: %v", raw, err)
	}
	return &ep
}
