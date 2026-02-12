package tests

import (
	"net/url"
	"strings"
	"testing"
)

func TestRedactURLCaseInsensitiveSensitiveKeys(t *testing.T) {
	raw := "https://user:secret@example.com/path?Token=abc&PASSWORD=xyz&Api_Key=k123&normal=ok"
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	got := httpRedactURL(u)
	ru, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse redacted url: %v", err)
	}

	if ru.User != nil {
		t.Fatalf("expected userinfo to be removed, got %v", ru.User)
	}

	q := ru.Query()
	if q.Get("Token") != "[REDACTED]" {
		t.Fatalf("expected Token redacted, got %q", q.Get("Token"))
	}
	if q.Get("PASSWORD") != "[REDACTED]" {
		t.Fatalf("expected PASSWORD redacted, got %q", q.Get("PASSWORD"))
	}
	if q.Get("Api_Key") != "[REDACTED]" {
		t.Fatalf("expected Api_Key redacted, got %q", q.Get("Api_Key"))
	}
	if q.Get("normal") != "ok" {
		t.Fatalf("expected normal query untouched, got %q", q.Get("normal"))
	}

	if strings.Contains(got, "secret") || strings.Contains(got, "abc") || strings.Contains(got, "xyz") {
		t.Fatalf("redacted url still contains sensitive data: %s", got)
	}
}
