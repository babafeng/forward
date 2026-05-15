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

func TestParseNodeSupportsLocalSubscribesWithForward(t *testing.T) {
	cfg, err := Parse([]byte(`{
  "nodes": [
    {
      "name": "subscribe",
      "listen": "socks5://admin:Python2026@:33333",
      "subscribes": [
        "/tmp/aaa.txt",
        "http://1.2.3.4:8080",
        "https://example.com/"
      ],
      "forward": "vless://0e467f5f-0a5c-44f8-82a5-07f803d161e8@example.com:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=A0ADElLyacApk2_prdYRh_lsOhG7dMeEVLc_NVFRGA8&security=reality&sid=d003cb13&sni=swscan.apple.com&type=tcp&mux=true&mux_max_streams=64&mux_idle=120s#VLESS-Reality"
    }
  ],
  "debug": false
}`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(cfg.Nodes) != 1 {
		t.Fatalf("nodes length = %d, want 1", len(cfg.Nodes))
	}

	node := cfg.Nodes[0]
	if node.Name != "subscribe" {
		t.Fatalf("node name = %q, want subscribe", node.Name)
	}
	if len(node.Listeners) != 1 {
		t.Fatalf("listeners length = %d, want 1", len(node.Listeners))
	}
	listen := node.Listeners[0]
	if listen.Scheme != "socks5" || listen.Port != 33333 {
		t.Fatalf("listen = %#v", listen)
	}
	user, pass, ok := listen.UserPass()
	if !ok || user != "admin" || pass != "Python2026" {
		t.Fatalf("listen auth = (%q, %q, %v)", user, pass, ok)
	}

	wantSubscribes := []string{
		"/tmp/aaa.txt",
		"http://1.2.3.4:8080",
		"https://example.com/",
	}
	gotSubscribes := node.EffectiveSubscribeURLs()
	if len(gotSubscribes) != len(wantSubscribes) {
		t.Fatalf("subscribes length = %d, want %d", len(gotSubscribes), len(wantSubscribes))
	}
	for i := range wantSubscribes {
		if gotSubscribes[i] != wantSubscribes[i] {
			t.Fatalf("subscribes[%d] = %q, want %q", i, gotSubscribes[i], wantSubscribes[i])
		}
	}

	if node.Forward == nil || len(node.ForwardChain) != 1 {
		t.Fatalf("forward = %#v, chain length = %d", node.Forward, len(node.ForwardChain))
	}
	forward := node.ForwardChain[0]
	if forward.Scheme != "vless" || forward.Host != "example.com" || forward.Port != 443 {
		t.Fatalf("forward = %#v", forward)
	}
	if forward.Query.Get("mux") != "true" || forward.Query.Get("security") != "reality" {
		t.Fatalf("forward query = %v", forward.Query)
	}
}
