package builder

import (
	"forward/base/endpoint"
	"testing"
	"time"
)

func TestParseDialPoolConfig(t *testing.T) {
	ep, err := endpoint.Parse("socks5://127.0.0.1:1080?pool_size=16&pool_ttl=45s")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	enabled, size, ttl := parseDialPoolConfig(ep)
	if !enabled {
		t.Fatalf("pool enabled = false, want true")
	}
	if size != 16 {
		t.Fatalf("pool size = %d, want 16", size)
	}
	if ttl != 45*time.Second {
		t.Fatalf("pool ttl = %s, want 45s", ttl)
	}
}

func TestParseDialPoolConfigInvalidFallback(t *testing.T) {
	ep, err := endpoint.Parse("socks5://127.0.0.1:1080?pool_size=abc&pool_ttl=20")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	enabled, size, ttl := parseDialPoolConfig(ep)
	if !enabled {
		t.Fatalf("pool enabled = false, want true")
	}
	if size != 0 {
		t.Fatalf("pool size = %d, want 0", size)
	}
	if ttl != 20*time.Second {
		t.Fatalf("pool ttl = %s, want 20s", ttl)
	}

	ep, err = endpoint.Parse("socks5://127.0.0.1:1080?pool_size=8&pool_ttl=bad")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	enabled, size, ttl = parseDialPoolConfig(ep)
	if !enabled {
		t.Fatalf("pool enabled = false, want true")
	}
	if size != 8 {
		t.Fatalf("pool size = %d, want 8", size)
	}
	if ttl != 0 {
		t.Fatalf("pool ttl = %s, want 0", ttl)
	}
}

func TestParseDialPoolConfigDefaultDisabled(t *testing.T) {
	ep, err := endpoint.Parse("socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	enabled, size, ttl := parseDialPoolConfig(ep)
	if enabled {
		t.Fatalf("pool enabled = true, want false")
	}
	if size != 0 {
		t.Fatalf("pool size = %d, want 0", size)
	}
	if ttl != 0 {
		t.Fatalf("pool ttl = %s, want 0", ttl)
	}
}

func TestParseDialPoolConfigEnableSwitch(t *testing.T) {
	ep, err := endpoint.Parse("socks5://127.0.0.1:1080?pool=true")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	enabled, size, ttl := parseDialPoolConfig(ep)
	if !enabled {
		t.Fatalf("pool enabled = false, want true")
	}
	if size != 0 {
		t.Fatalf("pool size = %d, want 0", size)
	}
	if ttl != 0 {
		t.Fatalf("pool ttl = %s, want 0", ttl)
	}

	ep, err = endpoint.Parse("socks5://127.0.0.1:1080?pool=false&pool_size=16&pool_ttl=60s")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	enabled, size, ttl = parseDialPoolConfig(ep)
	if enabled {
		t.Fatalf("pool enabled = true, want false")
	}
	if size != 0 || ttl != 0 {
		t.Fatalf("pool config = (%d,%s), want (0,0)", size, ttl)
	}
}
