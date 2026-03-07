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
		parts = append(parts, summarizeNode(node))
	}
	if len(parts) == 0 {
		return "DIRECT"
	}
	return strings.Join(parts, " -> ")
}

func summarizeNode(node *Node) string {
	if node == nil {
		return ""
	}
	if node.Display != "" {
		return "[" + node.Display + "]"
	}
	name := node.Name
	if name == "" {
		return node.Addr
	}
	if node.Addr != "" && name != node.Addr {
		return name + "(" + node.Addr + ")"
	}
	return name
}
