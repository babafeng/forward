package chain

import "strings"

// RouteSummary 返回路由的可读描述
// 用于日志和调试输出，避免各 handler 中重复实现
func RouteSummary(rt Route) string {
	if rt == nil {
		return "DIRECT"
	}
	nodes := rt.Nodes()
	if len(nodes) == 0 {
		return "DIRECT"
	}
	parts := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if node.Display != "" {
			parts = append(parts, node.Display)
			continue
		}
		name := node.Name
		if name == "" {
			name = node.Addr
		} else if node.Addr != "" && name != node.Addr {
			name = name + "(" + node.Addr + ")"
		}
		parts = append(parts, name)
	}
	if len(parts) == 0 {
		return "DIRECT"
	}
	return strings.Join(parts, " -> ")
}
