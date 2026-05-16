// Package encoding 提供通用编解码工具。
package encoding

import (
	"encoding/base64"
	"strings"
)

// DecodeBase64Flexible 依次尝试标准、无 padding、URL-safe、URL-safe 无 padding 四种
// base64 变体解码，返回首个成功结果。若全部失败则返回 (nil, false)。
func DecodeBase64Flexible(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if v, err := enc.DecodeString(s); err == nil {
			return v, true
		}
	}
	return nil, false
}
