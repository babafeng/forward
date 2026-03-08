package app

import (
	"testing"
	"time"

	"forward/base/endpoint"
	"forward/internal/config"
)

func TestRouterCacheReusesBuiltRouter(t *testing.T) {
	cache := newRouterCache()
	cfg := config.Config{
		NodeName:    "node-a",
		DialTimeout: time.Second,
	}

	first, err := cache.getOrBuild(cfg)
	if err != nil {
		t.Fatalf("first build error: %v", err)
	}
	second, err := cache.getOrBuild(cfg)
	if err != nil {
		t.Fatalf("second build error: %v", err)
	}

	if first != second {
		t.Fatalf("router cache returned different router instances for identical config")
	}
}

func TestRouterCacheSeparatesDifferentRouteInputs(t *testing.T) {
	cache := newRouterCache()
	forward, err := endpoint.Parse("socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatalf("parse forward endpoint: %v", err)
	}

	baseCfg := config.Config{
		NodeName:    "node-a",
		DialTimeout: time.Second,
	}
	chainCfg := baseCfg
	chainCfg.ForwardChain = []endpoint.Endpoint{forward}

	first, err := cache.getOrBuild(baseCfg)
	if err != nil {
		t.Fatalf("base build error: %v", err)
	}
	second, err := cache.getOrBuild(chainCfg)
	if err != nil {
		t.Fatalf("chain build error: %v", err)
	}

	if first == second {
		t.Fatalf("router cache reused router across different route inputs")
	}
}
