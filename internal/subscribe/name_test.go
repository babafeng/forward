package subscribe

import "testing"

func TestNormalizeProxyNameRemovesFlag(t *testing.T) {
	if got := NormalizeProxyName("🇺🇲 美国 | V1 | 03"); got != "美国 | V1 | 03" {
		t.Fatalf("NormalizeProxyName = %q, want %q", got, "美国 | V1 | 03")
	}
}

func TestParseNormalizesProxyNames(t *testing.T) {
	proxies, err := Parse([]byte(`
proxies:
  - name: "🇺🇲 美国 | V1 | 03"
    type: vmess
    server: 127.0.0.1
    port: 10086
    uuid: "11111111-1111-1111-1111-111111111111"
    alterId: 0
    cipher: auto
`))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("len(proxies) = %d, want 1", len(proxies))
	}
	if got := proxies[0].Name; got != "美国 | V1 | 03" {
		t.Fatalf("proxy name = %q, want %q", got, "美国 | V1 | 03")
	}
}
