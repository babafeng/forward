package app

import (
	"reflect"
	"testing"

	"forward/internal/config"
)

func TestApplySubscribeOptionsPreservesConfigWhenCLIUnset(t *testing.T) {
	cfg := config.Config{
		SubscribeURL:    "https://sub.example.com/a",
		SubscribeURLs:   []string{"https://sub.example.com/a"},
		SubscribeFilter: "香港",
		SubscribeUpdate: 15,
	}

	applySubscribeOptions(&cfg, subscribeOptions{
		Update: 60,
	})

	if cfg.SubscribeFilter != "香港" {
		t.Fatalf("SubscribeFilter = %q, want %q", cfg.SubscribeFilter, "香港")
	}
	if cfg.SubscribeUpdate != 15 {
		t.Fatalf("SubscribeUpdate = %d, want %d", cfg.SubscribeUpdate, 15)
	}
	if !reflect.DeepEqual(cfg.SubscribeURLs, []string{"https://sub.example.com/a"}) {
		t.Fatalf("SubscribeURLs = %v, want %v", cfg.SubscribeURLs, []string{"https://sub.example.com/a"})
	}
}

func TestApplySubscribeOptionsOverridesConfigWhenCLISet(t *testing.T) {
	cfg := config.Config{
		SubscribeURL:    "https://sub.example.com/a",
		SubscribeURLs:   []string{"https://sub.example.com/a"},
		SubscribeFilter: "香港",
		SubscribeUpdate: 15,
	}

	applySubscribeOptions(&cfg, subscribeOptions{
		URLs:      []string{"https://sub.example.com/b", "https://sub.example.com/c"},
		Filter:    "日本",
		Update:    0,
		URLsSet:   true,
		FilterSet: true,
		UpdateSet: true,
	})

	if cfg.SubscribeURL != "https://sub.example.com/b" {
		t.Fatalf("SubscribeURL = %q, want %q", cfg.SubscribeURL, "https://sub.example.com/b")
	}
	if !reflect.DeepEqual(cfg.SubscribeURLs, []string{"https://sub.example.com/b", "https://sub.example.com/c"}) {
		t.Fatalf("SubscribeURLs = %v, want %v", cfg.SubscribeURLs, []string{"https://sub.example.com/b", "https://sub.example.com/c"})
	}
	if cfg.SubscribeFilter != "日本" {
		t.Fatalf("SubscribeFilter = %q, want %q", cfg.SubscribeFilter, "日本")
	}
	if cfg.SubscribeUpdate != 0 {
		t.Fatalf("SubscribeUpdate = %d, want %d", cfg.SubscribeUpdate, 0)
	}
}
