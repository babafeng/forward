package tests

import (
	"context"
	"testing"

	"forward/internal/logging"
	"forward/internal/route"
)

func TestRouteVia_NilStore(t *testing.T) {
	ctx := context.Background()
	log := logging.New(logging.Options{Level: logging.LevelOff})

	via, err := route.RouteVia(ctx, nil, log, "192.168.1.1:12345", "example.com:443")
	if err != nil {
		t.Errorf("RouteVia with nil store should not error: %v", err)
	}
	if via != "DIRECT" {
		t.Errorf("RouteVia with nil store should return DIRECT, got %s", via)
	}
}

func TestRouteVia_IsReject(t *testing.T) {
	tests := []struct {
		via      string
		expected bool
	}{
		{"REJECT", true},
		{"reject", true},
		{"Reject", true},
		{"DIRECT", false},
		{"direct", false},
		{"PROXY_SG", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.via, func(t *testing.T) {
			result := route.IsReject(tt.via)
			if result != tt.expected {
				t.Errorf("IsReject(%q) = %v, want %v", tt.via, result, tt.expected)
			}
		})
	}
}
