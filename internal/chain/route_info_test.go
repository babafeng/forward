package chain

import "testing"

func TestRouteSummaryWrapsDisplayName(t *testing.T) {
	rt := NewRoute(
		&Node{Display: "美国 | V1 | 03"},
		&Node{Name: "vless_2", Addr: "us.babafeng.icu:443"},
	)

	if got := RouteSummary(rt); got != "[美国 | V1 | 03] -> vless_2(us.babafeng.icu:443)" {
		t.Fatalf("RouteSummary = %q, want %q", got, "[美国 | V1 | 03] -> vless_2(us.babafeng.icu:443)")
	}
}

func TestLabelNodeWrapsDisplayName(t *testing.T) {
	if got := labelNode(&Node{Display: "美国 | V1 | 03"}); got != "[美国 | V1 | 03]" {
		t.Fatalf("labelNode = %q, want %q", got, "[美国 | V1 | 03]")
	}
}
