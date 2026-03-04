package subscribe

import (
	"strings"
)

// FilterProxies 根据过滤表达式筛选代理节点。
//
// 过滤语法:
//   - | 表示或 (OR)
//   - & 表示与 (AND)
//   - ?! 表示非 (NOT)
//   - () 括号分割子组
//
// 示例:
//   - "美国|US" — 名称包含"美国"或"US"
//   - "?!日本&?!JP" — 排除包含"日本"和"JP"的节点
//   - "(?!日本试用|JP试用)&(美国|US|日本|JP)" — 排除日本试用/JP试用，且保留美国/US/日本/JP
func FilterProxies(proxies []ClashProxy, expr string) []ClashProxy {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return proxies
	}

	matcher := parseExpr(expr)

	var result []ClashProxy
	for _, p := range proxies {
		if matcher(p.Name) {
			result = append(result, p)
		}
	}
	return result
}

// matchFunc 是一个匹配函数，接受节点名称返回是否匹配。
type matchFunc func(name string) bool

// parseExpr 解析顶层表达式，按 & 分割为 AND 条件组。
func parseExpr(expr string) matchFunc {
	groups := splitTopLevel(expr, '&')

	matchers := make([]matchFunc, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		matchers = append(matchers, parseGroup(g))
	}

	if len(matchers) == 0 {
		return func(string) bool { return true }
	}

	// 所有 AND 条件都需要满足
	return func(name string) bool {
		for _, m := range matchers {
			if !m(name) {
				return false
			}
		}
		return true
	}
}

// parseGroup 解析一个条件组（可能带括号）。
func parseGroup(group string) matchFunc {
	// 去掉最外层括号
	group = stripParens(group)

	// 检查是否是否定条件组: ?!xxx|yyy
	if strings.HasPrefix(group, "?!") {
		inner := group[2:]
		// 按 | 分割 OR 条件
		parts := splitTopLevel(inner, '|')
		orMatchers := make([]matchFunc, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			// 检查内部是否也有 ?! 前缀（处理 ?!A|?!B 形式）
			if strings.HasPrefix(p, "?!") {
				keyword := p[2:]
				orMatchers = append(orMatchers, func(name string) bool {
					return strings.Contains(name, keyword)
				})
			} else {
				kw := p
				orMatchers = append(orMatchers, func(name string) bool {
					return strings.Contains(name, kw)
				})
			}
		}

		// 取反：只要匹配到任何一个 OR 条件就排除
		return func(name string) bool {
			for _, m := range orMatchers {
				if m(name) {
					return false
				}
			}
			return true
		}
	}

	// 正向匹配：按 | 分割 OR 条件
	parts := splitTopLevel(group, '|')
	orMatchers := make([]matchFunc, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// 每个 part 可能是 ?!keyword 或 keyword
		if strings.HasPrefix(p, "?!") {
			keyword := p[2:]
			orMatchers = append(orMatchers, func(name string) bool {
				return !strings.Contains(name, keyword)
			})
		} else {
			kw := p
			orMatchers = append(orMatchers, func(name string) bool {
				return strings.Contains(name, kw)
			})
		}
	}

	if len(orMatchers) == 0 {
		return func(string) bool { return true }
	}

	// 任意一个 OR 条件满足即可
	return func(name string) bool {
		for _, m := range orMatchers {
			if m(name) {
				return true
			}
		}
		return false
	}
}

// splitTopLevel 在顶层（不在括号内）按指定分隔符分割字符串。
func splitTopLevel(s string, sep byte) []string {
	var result []string
	depth := 0
	start := 0

	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case sep:
			if depth == 0 {
				result = append(result, s[start:i])
				start = i + 1
			}
		}
	}
	result = append(result, s[start:])
	return result
}

// stripParens 去掉最外层的匹配括号。
func stripParens(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		// 检查括号是否真的匹配
		depth := 0
		matched := true
		for i, c := range s {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
			}
			// 如果在遍历到最后一个字符之前 depth 就降为 0，
			// 说明第一个 ( 对应的 ) 不是最后一个字符
			if depth == 0 && i < len(s)-1 {
				matched = false
				break
			}
		}
		if matched {
			s = strings.TrimSpace(s[1 : len(s)-1])
		} else {
			break
		}
	}
	return s
}
