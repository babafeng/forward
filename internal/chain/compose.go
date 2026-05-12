package chain

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	ictx "forward/internal/ctx"
)

// ComposeRoute prepends prefix onto suffix. When prefix is a balancer route,
// the composed route reuses the balancer's live candidate selection so logs and
// dialing reflect the selected subscription node plus the appended suffix hops.
func ComposeRoute(prefix, suffix Route) Route {
	if suffix == nil {
		return prefix
	}
	suffixNodes := cloneNodes(suffix.Nodes())
	if len(suffixNodes) == 0 {
		return prefix
	}
	if prefix == nil {
		return NewRoute(suffixNodes...)
	}
	if br, ok := prefix.(*BalancerRoute); ok {
		return &composedBalancerRoute{
			prefix:      br,
			suffixNodes: suffixNodes,
		}
	}
	prefixNodes := cloneNodes(prefix.Nodes())
	if len(prefixNodes) == 0 {
		return NewRoute(suffixNodes...)
	}
	nodes := append(prefixNodes, suffixNodes...)
	return NewRoute(nodes...)
}

type composedBalancerRoute struct {
	prefix      *BalancerRoute
	suffixNodes []*Node
}

func (r *composedBalancerRoute) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if r == nil {
		return NewRoute().Dial(ctx, network, address)
	}
	if r.prefix == nil {
		return NewRoute(cloneNodes(r.suffixNodes)...).Dial(ctx, network, address)
	}
	if r.prefix.AllFailed() {
		return NewRoute(cloneNodes(r.suffixNodes)...).Dial(ctx, network, address)
	}

	r.prefix.mu.RLock()
	nodes := append([]*Node(nil), r.prefix.sortedNodes...)
	// 计算同延迟组
	topGroupSize := 1
	if len(nodes) > 0 {
		bestLat := r.prefix.latencies[nodes[0]]
		if bestLat < time.Hour*24 {
			for i := 1; i < len(nodes); i++ {
				lat := r.prefix.latencies[nodes[i]]
				if lat >= time.Hour*24 || lat-bestLat > r.prefix.latencyTolerance {
					break
				}
				topGroupSize++
			}
		}
	}
	r.prefix.mu.RUnlock()

	if len(nodes) == 0 {
		return nil, fmt.Errorf("balancer: no nodes available")
	}

	tr := ictx.TraceFromContext(ctx)
	hasTraceLog := tr != nil && tr.Logger != nil
	verbose := hasTraceLog && tr.Verbose
	start := time.Now()
	var lastErr error

	// 组内轮询选择起始节点
	rrIdx := r.prefix.rrIndex.Add(1) - 1
	startInGroup := int(rrIdx % uint64(topGroupSize))

	for tried := 0; tried < len(nodes); tried++ {
		var idx int
		if tried < topGroupSize {
			idx = (startInGroup + tried) % topGroupSize
		} else {
			idx = tried
		}
		node := nodes[idx]

		r.prefix.mu.RLock()
		latency := r.prefix.latencies[node]
		r.prefix.mu.RUnlock()

		if latency >= time.Hour*24 && tried > 0 {
			break
		}

		rt := r.candidateRoute(node)
		if verbose {
			tr.Logger.Debug("%sdial balancer try=%d node=%s addr=%s target=%s", tr.Prefix(), tried+1, labelNode(node), node.Addr, address)
		}

		cc, err := rt.Dial(ctx, network, address)
		if err != nil {
			lastErr = err
			if verbose {
				tr.Logger.Debug("%sdial balancer try=%d route err node=%s: %v", tr.Prefix(), tried+1, labelNode(node), err)
			}
			r.prefix.mu.Lock()
			r.prefix.latencies[node] = time.Hour * 24
			r.prefix.mu.Unlock()
			continue
		}

		if hasTraceLog {
			tr.Logger.Info("%s%s -> %s -> %s %s via %s", tr.Prefix(), tr.Src, tr.Local, strings.ToUpper(network), address, RouteSummary(rt))
		}
		return cc, nil
	}

	if hasTraceLog {
		tr.Logger.Debug("%sdial fail balancer %s %s err=%v dur=%s", tr.Prefix(), strings.ToUpper(network), address, lastErr, time.Since(start))
	}

	select {
	case r.prefix.retestCh <- struct{}{}:
	default:
	}

	r.prefix.mu.Lock()
	cb := r.prefix.onAllFailed
	now := time.Now()
	throttled := now.Sub(r.prefix.lastAllFailed) < 5*time.Minute
	if cb != nil && !throttled {
		r.prefix.lastAllFailed = now
	}
	r.prefix.mu.Unlock()
	if cb != nil && !throttled {
		go cb()
	}

	return nil, fmt.Errorf("balancer all nodes failed, last err: %v", lastErr)
}

func (r *composedBalancerRoute) Nodes() []*Node {
	if r == nil {
		return nil
	}
	var prefixNodes []*Node
	if r.prefix != nil {
		prefixNodes = r.prefix.Nodes()
	}
	out := make([]*Node, 0, len(prefixNodes)+len(r.suffixNodes))
	out = append(out, prefixNodes...)
	out = append(out, r.suffixNodes...)
	return out
}

func (r *composedBalancerRoute) Close() {
	if r == nil {
		return
	}
	for _, node := range r.suffixNodes {
		if node == nil {
			continue
		}
		if tr := node.Transport(); tr != nil {
			if closer, ok := tr.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
		}
	}
}

func (r *composedBalancerRoute) candidateRoute(node *Node) Route {
	if node == nil {
		return NewRoute(cloneNodes(r.suffixNodes)...)
	}
	base := []*Node{node}
	if rt := r.prefix.routeForNode(node); rt != nil {
		if nodes := rt.Nodes(); len(nodes) > 0 {
			base = nodes
		}
	}
	nodes := make([]*Node, 0, len(base)+len(r.suffixNodes))
	nodes = append(nodes, base...)
	nodes = append(nodes, r.suffixNodes...)
	return NewRoute(nodes...)
}

func cloneNodes(nodes []*Node) []*Node {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]*Node, 0, len(nodes))
	for _, node := range nodes {
		if node == nil {
			continue
		}
		var tr Transporter
		if node.transport != nil {
			tr = node.transport.Copy()
		}
		out = append(out, &Node{
			Name:      node.Name,
			Addr:      node.Addr,
			Display:   node.Display,
			transport: tr,
		})
	}
	return out
}
