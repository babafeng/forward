package tests

import (
	"testing"
	"time"

	"forward/internal/config"
)

func TestDefaultConstants(t *testing.T) {
	tests := []struct {
		name  string
		value time.Duration
		want  time.Duration
	}{
		{"DefaultDialTimeout", config.DefaultDialTimeout, 10 * time.Second},
		{"DefaultDialKeepAlive", config.DefaultDialKeepAlive, 30 * time.Second},
		{"DefaultUDPIdleTimeout", config.DefaultUDPIdleTimeout, 2 * time.Minute},
		{"DefaultReadDeadline", config.DefaultReadDeadline, 1 * time.Second},
		{"DefaultInitialBackoff", config.DefaultInitialBackoff, 2 * time.Second},
		{"DefaultMaxBackoff", config.DefaultMaxBackoff, 30 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.value, tt.want)
			}
		})
	}
}

func TestBufferSizeConstants(t *testing.T) {
	if config.DefaultBufferSize != 64*1024 {
		t.Errorf("DefaultBufferSize = %d, want %d", config.DefaultBufferSize, 64*1024)
	}
	if config.DefaultCopyBuffer != 32*1024 {
		t.Errorf("DefaultCopyBuffer = %d, want %d", config.DefaultCopyBuffer, 32*1024)
	}
}

func TestRunModeString(t *testing.T) {
	tests := []struct {
		mode config.RunMode
		want string
	}{
		{config.ModeUnknown, "unknown"},
		{config.ModeProxyServer, "proxy_server"},
		{config.ModeReverseClient, "reverse_client"},
		{config.ModeReverseServer, "reverse_server"},
		{config.ModePortForward, "port_forward"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.want {
				t.Errorf("RunMode.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfigIsMode(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeProxyServer}

	if !cfg.IsMode(config.ModeProxyServer) {
		t.Error("IsMode(ModeProxyServer) should return true")
	}
	if cfg.IsMode(config.ModePortForward) {
		t.Error("IsMode(ModePortForward) should return false")
	}
}
