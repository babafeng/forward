package app

import "testing"

func TestShouldManageTProxyRulesForDirectTProxyArgs(t *testing.T) {
	t.Parallel()

	cfg, _, err := parseArgs([]string{
		"-T", "12345",
		"-F", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpvYXVZYTU2N2VoUHp6ZEFHaWNDdUAyMDcuNTYuMTM3LjkwOjQyMjMy#ss-clash",
	})
	if err != nil {
		t.Fatalf("parseArgs error: %v", err)
	}
	if cfg.TProxy == nil {
		t.Fatal("cfg.TProxy should not be nil")
	}
	if !shouldManageTProxyRules(cfg) {
		t.Fatal("shouldManageTProxyRules should be true for direct -T startup")
	}
}
