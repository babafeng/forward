package subscribe

import "strings"

// NormalizeProxyName removes regional-indicator flag runes from subscription
// node names and collapses whitespace so downstream filtering/logging uses a
// stable display name.
func NormalizeProxyName(name string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 0x1F1E6 && r <= 0x1F1FF:
			return -1
		case r == '\u200D', r == '\uFE0F':
			return -1
		default:
			return r
		}
	}, name)
	return strings.TrimSpace(strings.Join(strings.Fields(cleaned), " "))
}

func normalizeProxyNames(proxies []ClashProxy) []ClashProxy {
	for i := range proxies {
		proxies[i].Name = NormalizeProxyName(proxies[i].Name)
	}
	return proxies
}
