package config

import "testing"

func TestSplitCSVValuesAndResolvePrimarySubscribe(t *testing.T) {
	urls := SplitCSVValues([]string{
		"https://sub-a.example.com/api, https://sub-b.example.com/api",
		"https://sub-b.example.com/api",
		" https://sub-c.example.com/api ",
	})
	if len(urls) != 4 {
		t.Fatalf("urls length = %d, want %d", len(urls), 4)
	}

	primary, normalized := ResolvePrimarySubscribe(
		"https://legacy.example.com/sub",
		"",
		urls,
	)
	if primary != "https://legacy.example.com/sub" {
		t.Fatalf("primary = %q, want %q", primary, "https://legacy.example.com/sub")
	}
	if len(normalized) != 4 {
		t.Fatalf("normalized length = %d, want %d", len(normalized), 4)
	}
}

func TestParseEndpointsReturnsFailingIndex(t *testing.T) {
	_, idx, err := ParseEndpoints([]string{
		"http://127.0.0.1:1080",
		"://bad-endpoint",
	})
	if err == nil {
		t.Fatal("ParseEndpoints should fail")
	}
	if idx != 1 {
		t.Fatalf("idx = %d, want %d", idx, 1)
	}
}
