package app

import (
	"reflect"
	"testing"
)

func TestParseArgsSubscribeURLsRepeatedAndCommaSeparated(t *testing.T) {
	cfg, opts, err := parseArgs([]string{
		"-L", "http://:1080",
		"-S", "https://sub-a.example.com/api, https://sub-b.example.com/api",
		"--subscribe", "https://sub-c.example.com/api",
		"-S", "https://sub-b.example.com/api",
	})
	if err != nil {
		t.Fatalf("parseArgs error: %v", err)
	}

	want := []string{
		"https://sub-a.example.com/api",
		"https://sub-b.example.com/api",
		"https://sub-c.example.com/api",
	}
	if !reflect.DeepEqual(opts.URLs, want) {
		t.Fatalf("opts.URLs = %v, want %v", opts.URLs, want)
	}
	if !reflect.DeepEqual(cfg.SubscribeURLs, want) {
		t.Fatalf("cfg.SubscribeURLs = %v, want %v", cfg.SubscribeURLs, want)
	}
	if cfg.SubscribeURL != want[0] {
		t.Fatalf("cfg.SubscribeURL = %q, want %q", cfg.SubscribeURL, want[0])
	}
}
