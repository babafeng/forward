package subscribe

import (
	"testing"
)

func TestFilterInclude(t *testing.T) {
	proxies := []ClashProxy{
		{Name: "🇺🇲 美国 | V1 | 01"},
		{Name: "🇺🇲 US Node 02"},
		{Name: "🇯🇵 日本 | V1 | 01"},
		{Name: "🇯🇵 JP Node 02"},
		{Name: "🇭🇰 香港 | V1 | 01"},
		{Name: "🇸🇬 新加坡 | V1 | 01"},
	}

	result := FilterProxies(proxies, "美国|US")
	if len(result) != 2 {
		t.Errorf("期望 2 个节点，得到 %d 个: %v", len(result), names(result))
	}
	for _, r := range result {
		if r.Name != "🇺🇲 美国 | V1 | 01" && r.Name != "🇺🇲 US Node 02" {
			t.Errorf("不期望的节点: %s", r.Name)
		}
	}
}

func TestFilterExclude(t *testing.T) {
	proxies := []ClashProxy{
		{Name: "🇺🇲 美国 | V1 | 01"},
		{Name: "🇯🇵 日本 | V1 | 01"},
		{Name: "🇯🇵 JP Node 02"},
		{Name: "🇭🇰 香港 | V1 | 01"},
	}

	result := FilterProxies(proxies, "?!日本&?!JP")
	if len(result) != 2 {
		t.Errorf("期望 2 个节点，得到 %d 个: %v", len(result), names(result))
	}
	for _, r := range result {
		if r.Name == "🇯🇵 日本 | V1 | 01" || r.Name == "🇯🇵 JP Node 02" {
			t.Errorf("不应该包含节点: %s", r.Name)
		}
	}
}

func TestFilterComplex(t *testing.T) {
	proxies := []ClashProxy{
		{Name: "🇺🇲 美国 | V1 | 01"},
		{Name: "🇺🇲 US Node 02"},
		{Name: "🇯🇵 日本 | V1 | 01"},
		{Name: "🇯🇵 JP Node 02"},
		{Name: "🇯🇵 日本试用 | 01"},
		{Name: "🇯🇵 JP试用 Node"},
		{Name: "🇭🇰 香港 | V1 | 01"},
		{Name: "🇸🇬 新加坡 | V1 | 01"},
	}

	// 排除日本试用/JP试用，且保留美国/US/日本/JP
	result := FilterProxies(proxies, "(?!日本试用|JP试用)&(美国|US|日本|JP)")
	expectedNames := map[string]bool{
		"🇺🇲 美国 | V1 | 01": true,
		"🇺🇲 US Node 02":   true,
		"🇯🇵 日本 | V1 | 01": true,
		"🇯🇵 JP Node 02":   true,
	}

	if len(result) != len(expectedNames) {
		t.Errorf("期望 %d 个节点，得到 %d 个: %v", len(expectedNames), len(result), names(result))
	}
	for _, r := range result {
		if !expectedNames[r.Name] {
			t.Errorf("不期望的节点: %s", r.Name)
		}
	}
}

func TestFilterEmpty(t *testing.T) {
	proxies := []ClashProxy{
		{Name: "node1"},
		{Name: "node2"},
	}
	result := FilterProxies(proxies, "")
	if len(result) != 2 {
		t.Errorf("空过滤器应返回所有节点，得到 %d 个", len(result))
	}
}

func names(proxies []ClashProxy) []string {
	var n []string
	for _, p := range proxies {
		n = append(n, p.Name)
	}
	return n
}
