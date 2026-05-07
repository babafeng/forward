package app

import "testing"

func TestParseArgsAcceptsVmessBase64Forward(t *testing.T) {
	rawForward := "vmess://YXV0bzpjZTU5ZmJlYy0wNWQxLTQ3ZmMtYWMxZi03MmVjMjE5YTc1MzBAMS4yLjMuNDoxMjUyOQ?remarks=JMS-846412@example.com:12529&alterId=0"

	cfg, _, err := parseArgs([]string{"-T", "12345", "-F", rawForward})
	if err != nil {
		t.Fatalf("parseArgs() error = %v", err)
	}
	if len(cfg.ForwardChain) != 1 {
		t.Fatalf("ForwardChain length = %d, want 1", len(cfg.ForwardChain))
	}
	forward := cfg.ForwardChain[0]
	if forward.Scheme != "vmess" {
		t.Errorf("forward scheme = %q, want vmess", forward.Scheme)
	}
	if forward.Host != "1.2.3.4" {
		t.Errorf("forward host = %q, want 1.2.3.4", forward.Host)
	}
	if forward.Port != 12529 {
		t.Errorf("forward port = %d, want 12529", forward.Port)
	}
}
