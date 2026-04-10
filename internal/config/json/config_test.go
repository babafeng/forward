package json

import "testing"

func TestParseSupportsLegacySubscribeAndSubscribesArray(t *testing.T) {
	cfg, err := Parse([]byte(`{
  "listen": "http://127.0.0.1:1080",
  "subscribe": "https://legacy.example.com/sub",
  "subscribes": [
    "https://sub1.example.com/sub",
    " https://sub2.example.com/sub "
  ],
  "filter": "日本",
  "update": 15
}`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	want := []string{
		"https://legacy.example.com/sub",
		"https://sub1.example.com/sub",
		"https://sub2.example.com/sub",
	}
	got := cfg.EffectiveSubscribeURLs()
	if len(got) != len(want) {
		t.Fatalf("effective subscribe urls length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("effective subscribe urls[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if cfg.SubscribeFilter != "日本" {
		t.Fatalf("SubscribeFilter = %q, want %q", cfg.SubscribeFilter, "日本")
	}
	if cfg.SubscribeUpdate != 15 {
		t.Fatalf("SubscribeUpdate = %d, want %d", cfg.SubscribeUpdate, 15)
	}
}

func TestParseNodeSupportsSubscribesArray(t *testing.T) {
	cfg, err := Parse([]byte(`{
  "nodes": [
    {
      "name": "node-a",
      "listen": "http://127.0.0.1:1080",
      "subscribes": [
        "https://sub1.example.com/sub",
        "https://sub2.example.com/sub"
      ],
      "update": 20
    }
  ]
}`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(cfg.Nodes) != 1 {
		t.Fatalf("nodes length = %d, want 1", len(cfg.Nodes))
	}

	node := cfg.Nodes[0]
	want := []string{
		"https://sub1.example.com/sub",
		"https://sub2.example.com/sub",
	}
	got := node.EffectiveSubscribeURLs()
	if len(got) != len(want) {
		t.Fatalf("node effective subscribe urls length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("node effective subscribe urls[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if node.SubscribeUpdate != 20 {
		t.Fatalf("node SubscribeUpdate = %d, want %d", node.SubscribeUpdate, 20)
	}
}
