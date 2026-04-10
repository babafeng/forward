package metadata

import (
	"testing"
	"time"
)

func TestValueParsers(t *testing.T) {
	if got := StringValue("  example.com  "); got != "example.com" {
		t.Fatalf("StringValue = %q, want %q", got, "example.com")
	}
	if got := IntValue(" 42 "); got != 42 {
		t.Fatalf("IntValue = %d, want %d", got, 42)
	}
	if got := BoolValue("YeS"); !got {
		t.Fatal("BoolValue should accept yes")
	}
	if got := DurationValue("7"); got != 7*time.Second {
		t.Fatalf("DurationValue = %s, want %s", got, 7*time.Second)
	}
	if got := DurationValue("1500ms"); got != 1500*time.Millisecond {
		t.Fatalf("DurationValue = %s, want %s", got, 1500*time.Millisecond)
	}
}
