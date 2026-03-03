package chain

import (
	"context"
	"fmt"
	"net"
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
	latencies    map[*Node]time.Duration
	sortedNodes  []*Node // 根据延迟排序的节点
	testInterval time.Duration
	dialTimeout  time.Duration
	stopCh       chan struct{}
}

// NewBalancerRoute 创建一个新的负载均衡路由
func NewBalancerRoute(nodes []*Node, testInterval time.Duration, dialTimeout time.Duration) *BalancerRoute {
	if testInterval <= 0 {
		testInterval = 2 * time.Minute
	}
	if dialTimeout <= 0 {
		dialTimeout = config.DefaultDialTimeout
	}
	r := &BalancerRoute{
		nodes:        nodes,
		latencies:    make(map[*Node]time.Duration),
		sortedNodes:  make([]*Node, len(nodes)),
		testInterval: testInterval,
		dialTimeout:  dialTimeout,
		stopCh:       make(chan struct{}),
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
	close(r.stopCh)
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
		case <-r.stopCh:
			return
		}
	}
}

func (r *BalancerRoute) testAll() {
	if len(r.nodes) == 0 {
		return
	}
	var wg sync.WaitGroup
	type result struct {
		node    *Node
		latency time.Duration
	}
	results := make(chan result, len(r.nodes))

	for _, n := range r.nodes {
		wg.Add(1)
		go func(node *Node) {
			defer wg.Done()
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), r.dialTimeout)
			defer cancel()

			// 对于代理节点，测试底层连接和握手时间
			conn, err := node.Transport().Dial(ctx, node.Addr)
			if err != nil {
				results <- result{node: node, latency: time.Hour * 24} // 极大的值表示不可用
				return
			}
			conn, err = node.Transport().Handshake(ctx, conn)
			if err != nil {
				conn.Close()
				results <- result{node: node, latency: time.Hour * 24} // 握手失败
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

	// 更新排序
	var available []*Node
	var unavailable []*Node
	for _, n := range r.nodes {
		if r.latencies[n] >= time.Hour*24 {
			unavailable = append(unavailable, n)
		} else {
			available = append(available, n)
		}
	}

	// 对可用的按延迟排序，简单的冒泡排序或插入即可，节点不多
	for i := 0; i < len(available); i++ {
		for j := i + 1; j < len(available); j++ {
			if r.latencies[available[i]] > r.latencies[available[j]] {
				available[i], available[j] = available[j], available[i]
			}
		}
	}

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
	verbose := hasTraceLog && tr.Verbose

	start := time.Now()
	var lastErr error

	// 按顺序尝试最佳节点，最多尝试前3个，防止无限重试耗时太长
	maxTries := 3
	if len(nodes) < maxTries {
		maxTries = len(nodes)
	}

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

		conn, err := node.Transport().Dial(ctx, node.Addr)
		if err != nil {
			lastErr = err
			if verbose {
				tr.Logger.Debug("%sdial balancer try=%d dial err node=%s: %v", tr.Prefix(), i+1, labelNode(node), err)
			}
			// 失败时动态惩罚延迟
			r.mu.Lock()
			r.latencies[node] = time.Hour * 24
			r.mu.Unlock()
			continue
		}

		hc, err := node.Transport().Handshake(ctx, conn)
		if err != nil {
			conn.Close()
			lastErr = err
			if verbose {
				tr.Logger.Debug("%sdial balancer try=%d handshake err node=%s: %v", tr.Prefix(), i+1, labelNode(node), err)
			}
			r.mu.Lock()
			r.latencies[node] = time.Hour * 24
			r.mu.Unlock()
			continue
		}

		conn = hc

		cc, err := node.Transport().Connect(ctx, conn, network, address)
		if err != nil {
			conn.Close()
			lastErr = err
			if verbose {
				tr.Logger.Debug("%sdial balancer try=%d connect target err prev=%s -> %s %s: %v", tr.Prefix(), i+1, labelNode(node), strings.ToUpper(network), address, err)
			}
			r.mu.Lock()
			r.latencies[node] = time.Hour * 24
			r.mu.Unlock()
			continue
		}

		if hasTraceLog {
			tr.Logger.Debug("%sdial ok balancer %s %s via %s dur=%s", tr.Prefix(), strings.ToUpper(network), address, labelNode(node), time.Since(start))
		}
		return cc, nil
	}

	if hasTraceLog {
		tr.Logger.Debug("%sdial fail balancer %s %s err=%v dur=%s", tr.Prefix(), strings.ToUpper(network), address, lastErr, time.Since(start))
	}
	return nil, fmt.Errorf("balancer all nodes failed, last err: %v", lastErr)
}

func (r *BalancerRoute) Nodes() []*Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sortedNodes
}

// RouteSummary 返回简单的只包含单节点的总结
func RouteSummaryLoadBalanced(node *Node) string {
	return labelNode(node)
}
