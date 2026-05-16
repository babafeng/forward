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
		Nodes: []config.NodeConfig{{
			Name:            "node-a",
			SubscribeURL:    "https://node.example.com/a",
			SubscribeURLs:   []string{"https://node.example.com/a"},
			SubscribeFilter: "香港",
			SubscribeUpdate: 60,
		}},
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
	if got := cfg.Nodes[0].SubscribeURL; got != "https://sub.example.com/b" {
		t.Fatalf("node SubscribeURL = %q, want %q", got, "https://sub.example.com/b")
	}
	if !reflect.DeepEqual(cfg.Nodes[0].SubscribeURLs, []string{"https://sub.example.com/b", "https://sub.example.com/c"}) {
		t.Fatalf("node SubscribeURLs = %v, want %v", cfg.Nodes[0].SubscribeURLs, []string{"https://sub.example.com/b", "https://sub.example.com/c"})
	}
	if cfg.Nodes[0].SubscribeFilter != "日本" {
		t.Fatalf("node SubscribeFilter = %q, want %q", cfg.Nodes[0].SubscribeFilter, "日本")
	}
	if cfg.Nodes[0].SubscribeUpdate != 0 {
		t.Fatalf("node SubscribeUpdate = %d, want %d", cfg.Nodes[0].SubscribeUpdate, 0)
	}
}
