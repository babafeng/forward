package chain

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"forward/internal/config"
	ictx "forward/internal/ctx"
)

// BalancerRoute 实现了一个基于延迟测试的动态负载均衡转发链
type BalancerRoute struct {
	mu           sync.RWMutex
	nodes        []*Node
	routes       map[*Node]Route
	latencies    map[*Node]time.Duration
	sortedNodes  []*Node // 根据延迟排序的节点
	testInterval time.Duration
	dialTimeout  time.Duration
	stopCh       chan struct{}
	retestCh     chan struct{} // 用于触发即时重测
	closeOnce    sync.Once

	// 全部节点失败时的回调（可选），由上层注册用于紧急刷新订阅。
	onAllFailed   func()
	lastAllFailed time.Time // 节流：最短 5 分钟间隔
}

// BalancerCandidate 表示一个负载均衡候选项。
// Node 用于探测和排序；Route 为该候选的完整路由（可为多跳）。
// 若 Route 为空，则退化为使用 Node 自身进行单跳连接。
type BalancerCandidate struct {
	Node  *Node
	Route Route
}

// NewBalancerRoute 创建一个新的负载均衡路由
func NewBalancerRoute(nodes []*Node, testInterval time.Duration, dialTimeout time.Duration) *BalancerRoute {
	candidates := make([]BalancerCandidate, 0, len(nodes))
	for _, n := range nodes {
		if n == nil {
			continue
		}
		candidates = append(candidates, BalancerCandidate{Node: n})
	}
	return NewBalancerRouteWithCandidates(candidates, testInterval, dialTimeout)
}

// NewBalancerRouteWithCandidates 创建支持“候选节点 + 完整路由”的负载均衡路由。
func NewBalancerRouteWithCandidates(candidates []BalancerCandidate, testInterval time.Duration, dialTimeout time.Duration) *BalancerRoute {
	if testInterval <= 0 {
		testInterval = 2 * time.Minute
	}
	if dialTimeout <= 0 {
		dialTimeout = config.DefaultDialTimeout
	}

	nodes := make([]*Node, 0, len(candidates))
	routes := make(map[*Node]Route, len(candidates))
	for _, c := range candidates {
		if c.Node == nil {
			continue
		}
		nodes = append(nodes, c.Node)
		if c.Route != nil {
			routes[c.Node] = c.Route
		}
	}

	r := &BalancerRoute{
		nodes:        nodes,
		routes:       routes,
		latencies:    make(map[*Node]time.Duration),
		sortedNodes:  make([]*Node, len(nodes)),
		testInterval: testInterval,
		dialTimeout:  dialTimeout,
		stopCh:       make(chan struct{}),
		retestCh:     make(chan struct{}, 1),
	}
	copy(r.sortedNodes, nodes)
	// 初始化时给所有节点设置一个合理的默认延迟
	for _, n := range nodes {
		r.latencies[n] = 500 * time.Millisecond
	}

	go r.backgroundTest()
	return r
}

// Close 停止后台测速任务
func (r *BalancerRoute) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		close(r.stopCh)
		r.mu.RLock()
		routes := snapshotRoutes(r.routes)
		r.mu.RUnlock()
		closeRoutes(routes)
	})
}

// Done returns a channel that is closed when the balancer is stopped.
func (r *BalancerRoute) Done() <-chan struct{} {
	return r.stopCh
}

func (r *BalancerRoute) backgroundTest() {
	// 启动时立即测试一次
	r.testAll()

	ticker := time.NewTicker(r.testInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.testAll()
		case <-r.retestCh:
			r.testAll()
		case <-r.stopCh:
			return
		}
	}
}

func (r *BalancerRoute) testAll() {
	// Snapshot nodes under read lock to avoid data race with UpdateCandidates.
	r.mu.RLock()
	nodes := make([]*Node, len(r.nodes))
	copy(nodes, r.nodes)
	r.mu.RUnlock()

	if len(nodes) == 0 {
		return
	}
	var wg sync.WaitGroup
	type result struct {
		node    *Node
		latency time.Duration
	}
	results := make(chan result, len(nodes))

	for _, n := range nodes {
		wg.Add(1)
		go func(node *Node) {
			defer wg.Done()
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), r.dialTimeout)
			defer cancel()

			conn, err := node.Transport().Dial(ctx, node.Addr)
			if err != nil {
				results <- result{node: node, latency: time.Hour * 24}
				return
			}
			conn, err = node.Transport().Handshake(ctx, conn)
			if err != nil {
				conn.Close()
				results <- result{node: node, latency: time.Hour * 24}
				return
			}
			conn.Close()
			results <- result{node: node, latency: time.Since(start)}
		}(n)
	}

	wg.Wait()
	close(results)

	r.mu.Lock()
	defer r.mu.Unlock()

	for res := range results {
		r.latencies[res.node] = res.latency
	}

	var available []*Node
	var unavailable []*Node
	for _, n := range r.nodes {
		if r.latencies[n] >= time.Hour*24 {
			unavailable = append(unavailable, n)
		} else {
			available = append(available, n)
		}
	}

	sort.Slice(available, func(i, j int) bool {
		return r.latencies[available[i]] < r.latencies[available[j]]
	})

	r.sortedNodes = append(available, unavailable...)
}

func (r *BalancerRoute) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	r.mu.RLock()
	nodes := r.sortedNodes
	r.mu.RUnlock()

	if len(nodes) == 0 {
		return nil, fmt.Errorf("balancer: no nodes available")
	}

	tr := ictx.TraceFromContext(ctx)
	hasTraceLog := tr != nil && tr.Logger != nil

	// Print connection routing info
	if hasTraceLog {
		// Just print load balanced name for the balancer itself for now, or "Balancer"
		tr.Logger.Info("%s%s -> %s -> %s via %s", tr.Prefix(), tr.Src, tr.Local, address, "Balancer")
	}

	verbose := hasTraceLog && tr.Verbose

	start := time.Now()
	var lastErr error

	maxTries := len(nodes)

	for i := 0; i < maxTries; i++ {
		node := nodes[i]

		r.mu.RLock()
		latency := r.latencies[node]
		r.mu.RUnlock()

		// 如果就算是最好的也已经标为不可用，那基本上全挂了
		if latency >= time.Hour*24 && i > 0 {
			break
		}

		if verbose {
			tr.Logger.Debug("%sdial balancer try=%d node=%s addr=%s target=%s", tr.Prefix(), i+1, labelNode(node), node.Addr, address)
		}

		cc, err := r.dialCandidate(ctx, node, network, address)
		if err != nil {
			lastErr = err
			if verbose {
				tr.Logger.Debug("%sdial balancer try=%d route err node=%s: %v", tr.Prefix(), i+1, labelNode(node), err)
			}
			r.mu.Lock()
			r.latencies[node] = time.Hour * 24
			r.mu.Unlock()
			continue
		}

		if hasTraceLog {
			rt := r.routeForNode(node)
			var summary string
			if rt != nil {
				summary = RouteSummary(rt)
			} else {
				summary = labelNode(node)
			}
			tr.Logger.Info("%s%s -> %s -> %s via %s", tr.Prefix(), tr.Src, tr.Local, address, summary)
		}
		return cc, nil
	}

	if hasTraceLog {
		tr.Logger.Debug("%sdial fail balancer %s %s err=%v dur=%s", tr.Prefix(), strings.ToUpper(network), address, lastErr, time.Since(start))
	}

	// 所有节点失败：触发即时重测（非阻塞）
	select {
	case r.retestCh <- struct{}{}:
	default:
	}

	// 触发上层紧急回调（节流 5 分钟）
	r.mu.Lock()
	cb := r.onAllFailed
	now := time.Now()
	throttled := now.Sub(r.lastAllFailed) < 5*time.Minute
	if cb != nil && !throttled {
		r.lastAllFailed = now
	}
	r.mu.Unlock()
	if cb != nil && !throttled {
		go cb()
	}

	return nil, fmt.Errorf("balancer all nodes failed, last err: %v", lastErr)
}

func (r *BalancerRoute) dialCandidate(ctx context.Context, node *Node, network, address string) (net.Conn, error) {
	if node == nil {
		return nil, fmt.Errorf("balancer: nil node")
	}

	if rt := r.routeForNode(node); rt != nil {
		return rt.Dial(ctx, network, address)
	}

	conn, err := node.Transport().Dial(ctx, node.Addr)
	if err != nil {
		return nil, err
	}

	hc, err := node.Transport().Handshake(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	cc, err := node.Transport().Connect(ctx, hc, network, address)
	if err != nil {
		hc.Close()
		return nil, err
	}
	return cc, nil
}

func (r *BalancerRoute) routeForNode(node *Node) Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.routes == nil {
		return nil
	}
	return r.routes[node]
}

func (r *BalancerRoute) Nodes() []*Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sortedNodes
}

// SetOnAllFailed 注册一个回调，当所有节点都失败时调用。
// 回调会被节流为最短 5 分钟间隔，并在独立的 goroutine 中执行。
func (r *BalancerRoute) SetOnAllFailed(fn func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onAllFailed = fn
}

// RouteSummary 返回简单的只包含单节点的总结
func RouteSummaryLoadBalanced(node *Node) string {
	return labelNode(node)
}

// UpdateCandidates 热更新负载均衡候选节点
func (r *BalancerRoute) UpdateCandidates(candidates []BalancerCandidate) {
	if len(candidates) == 0 {
		return
	}

	nodes := make([]*Node, 0, len(candidates))
	routes := make(map[*Node]Route, len(candidates))
	newLatencies := make(map[*Node]time.Duration)

	// Build new structures
	for _, c := range candidates {
		if c.Node == nil {
			continue
		}
		nodes = append(nodes, c.Node)
		if c.Route != nil {
			routes[c.Node] = c.Route
		}
		// Default latency
		newLatencies[c.Node] = 500 * time.Millisecond
	}

	// Hot swap
	r.mu.Lock()
	oldRoutes := r.routes

	// Preserve latencies for identical nodes (matching address)
	addrLatencyMap := make(map[string]time.Duration)
	for _, oldNode := range r.nodes {
		if lat, ok := r.latencies[oldNode]; ok {
			addrLatencyMap[oldNode.Addr] = lat
		}
	}

	for _, newNode := range nodes {
		if lat, ok := addrLatencyMap[newNode.Addr]; ok {
			newLatencies[newNode] = lat
		}
	}

	r.nodes = nodes
	r.routes = routes
	r.latencies = newLatencies
	r.sortedNodes = make([]*Node, len(nodes))
	copy(r.sortedNodes, nodes)
	r.mu.Unlock()

	closeReplacedRoutes(oldRoutes, routes)

	// Trigger async test to sort the new nodes
	go r.testAll()
}

func snapshotRoutes(routes map[*Node]Route) []Route {
	if len(routes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(routes))
	out := make([]Route, 0, len(routes))
	for _, rt := range routes {
		key := routeKey(rt)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, rt)
	}
	return out
}

func closeReplacedRoutes(oldRoutes, newRoutes map[*Node]Route) {
	if len(oldRoutes) == 0 {
		return
	}
	keep := make(map[string]struct{}, len(newRoutes))
	for _, rt := range snapshotRoutes(newRoutes) {
		keep[routeKey(rt)] = struct{}{}
	}
	for _, rt := range snapshotRoutes(oldRoutes) {
		key := routeKey(rt)
		if _, ok := keep[key]; ok {
			continue
		}
		closeRoute(rt)
	}
}

func closeRoutes(routes []Route) {
	for _, rt := range routes {
		closeRoute(rt)
	}
}

func closeRoute(rt Route) {
	if rt == nil {
		return
	}
	if closer, ok := rt.(interface{ Close() }); ok {
		closer.Close()
		return
	}
	if closer, ok := rt.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

func routeKey(rt Route) string {
	if rt == nil {
		return ""
	}
	v := reflect.ValueOf(rt)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.UnsafePointer:
		if v.IsNil() {
			return ""
		}
		return fmt.Sprintf("%T:%x", rt, v.Pointer())
	default:
		return fmt.Sprintf("%T:%v", rt, rt)
	}
}
