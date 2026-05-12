package chain

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestBalancerRouteWithCandidatesDialUsesCandidateRoute(t *testing.T) {
	node := NewNode("sub", "127.0.0.1:1", &alwaysFailTransport{})
	fake := &fakeRoute{nodes: []*Node{node}}

	br := NewBalancerRouteWithCandidates([]BalancerCandidate{
		{
			Node:  node,
			Route: fake,
		},
	}, time.Hour, 30*time.Millisecond, "")
	defer br.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn, err := br.Dial(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("balancer dial error: %v", err)
	}
	if conn == nil {
		t.Fatal("balancer dial returned nil conn")
	}
	_ = conn.Close()

	if got := fake.calls.Load(); got == 0 {
		t.Fatalf("candidate route dial calls = %d, want > 0", got)
	}
}

type fakeRoute struct {
	nodes  []*Node
	calls  atomic.Int32
	closed atomic.Int32
}

func (r *fakeRoute) Dial(_ context.Context, _ string, _ string) (net.Conn, error) {
	r.calls.Add(1)
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

func (r *fakeRoute) Nodes() []*Node {
	return r.nodes
}

func (r *fakeRoute) Close() {
	r.closed.Add(1)
}

func TestBalancerRouteCloseClosesCandidateRoutes(t *testing.T) {
	node := NewNode("sub", "127.0.0.1:1", &alwaysFailTransport{})
	fake := &fakeRoute{nodes: []*Node{node}}

	br := NewBalancerRouteWithCandidates([]BalancerCandidate{
		{
			Node:  node,
			Route: fake,
		},
	}, time.Hour, 30*time.Millisecond, "")

	br.Close()

	if got := fake.closed.Load(); got != 1 {
		t.Fatalf("candidate route close count = %d, want 1", got)
	}
}

func TestBalancerRouteUpdateCandidatesClosesReplacedRoutes(t *testing.T) {
	oldNode := NewNode("old", "127.0.0.1:1", &alwaysFailTransport{})
	oldRoute := &fakeRoute{nodes: []*Node{oldNode}}
	br := NewBalancerRouteWithCandidates([]BalancerCandidate{
		{
			Node:  oldNode,
			Route: oldRoute,
		},
	}, time.Hour, 30*time.Millisecond, "")
	defer br.Close()

	newNode := NewNode("new", "127.0.0.1:2", &alwaysFailTransport{})
	newRoute := &fakeRoute{nodes: []*Node{newNode}}

	br.UpdateCandidates([]BalancerCandidate{
		{
			Node:  newNode,
			Route: newRoute,
		},
	})

	if got := oldRoute.closed.Load(); got != 1 {
		t.Fatalf("old route close count = %d, want 1", got)
	}
	if got := newRoute.closed.Load(); got != 0 {
		t.Fatalf("new route close count = %d, want 0 before balancer close", got)
	}
}

func TestBalancerRouteFallsBackAfterRetestConfirmsAllFailed(t *testing.T) {
	node := NewNode("sub", "127.0.0.1:1", &alwaysFailTransport{})
	fallbackNode := NewNode("vless_2", "95.40.82.122:443", &alwaysFailTransport{})
	fallback := &fakeRoute{nodes: []*Node{fallbackNode}}

	br := NewBalancerRouteWithCandidates([]BalancerCandidate{
		{
			Node: node,
		},
	}, time.Hour, 30*time.Millisecond, "")
	defer br.Close()
	br.SetFallbackRoute(fallback)

	br.testAll()
	if !br.AllFailed() {
		t.Fatal("AllFailed = false, want true after retest marks every candidate unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn, err := br.Dial(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	if conn == nil {
		t.Fatal("Dial returned nil conn")
	}
	_ = conn.Close()

	if got := fallback.calls.Load(); got == 0 {
		t.Fatalf("fallback dial calls = %d, want > 0", got)
	}
}

func TestBalancerRouteRoundRobinWithinTopGroup(t *testing.T) {
	// 3 个节点，延迟分别为 100ms、130ms、200ms
	// 前两个差距 <= 50ms，属于同延迟组；第三个不在同组
	node1 := NewNode("n1", "127.0.0.1:1", &alwaysFailTransport{})
	node2 := NewNode("n2", "127.0.0.1:2", &alwaysFailTransport{})
	node3 := NewNode("n3", "127.0.0.1:3", &alwaysFailTransport{})

	fake1 := &fakeRoute{nodes: []*Node{node1}}
	fake2 := &fakeRoute{nodes: []*Node{node2}}
	fake3 := &fakeRoute{nodes: []*Node{node3}}

	br := NewBalancerRouteWithCandidates([]BalancerCandidate{
		{Node: node1, Route: fake1},
		{Node: node2, Route: fake2},
		{Node: node3, Route: fake3},
	}, time.Hour, 30*time.Millisecond, "")
	defer br.Close()

	// 手动设置延迟和排序，绕过后台测试
	br.mu.Lock()
	br.latencies[node1] = 100 * time.Millisecond
	br.latencies[node2] = 130 * time.Millisecond
	br.latencies[node3] = 200 * time.Millisecond
	br.sortedNodes = []*Node{node1, node2, node3}
	br.mu.Unlock()

	// 多次 Dial，收集每次首选的节点
	selectedNodes := make(map[string]int)
	const dialCount = 10
	for i := 0; i < dialCount; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := br.Dial(ctx, "tcp", "example.com:443")
		cancel()
		if err != nil {
			t.Fatalf("Dial #%d error: %v", i, err)
		}
		_ = conn.Close()
	}

	// 统计 fake1 和 fake2 被调用的次数
	selectedNodes["n1"] = int(fake1.calls.Load())
	selectedNodes["n2"] = int(fake2.calls.Load())
	selectedNodes["n3"] = int(fake3.calls.Load())

	// 验证同延迟组内 (n1, n2) 都被调用过（轮询分散）
	if selectedNodes["n1"] == 0 {
		t.Errorf("node n1 was never selected, want round-robin within top group")
	}
	if selectedNodes["n2"] == 0 {
		t.Errorf("node n2 was never selected, want round-robin within top group")
	}
	// n3 不在同延迟组，不应该被优先调用
	if selectedNodes["n3"] > 0 {
		t.Errorf("node n3 (outside top group) was selected %d times, want 0", selectedNodes["n3"])
	}
	// 验证总调用次数
	total := selectedNodes["n1"] + selectedNodes["n2"]
	if total != dialCount {
		t.Errorf("top group total calls = %d, want %d", total, dialCount)
	}
	// 验证分布大致均匀（各 5 次）
	if selectedNodes["n1"] < 3 || selectedNodes["n2"] < 3 {
		t.Errorf("uneven distribution: n1=%d, n2=%d; want roughly equal", selectedNodes["n1"], selectedNodes["n2"])
	}
}

type alwaysFailTransport struct{}

func (t *alwaysFailTransport) Dial(_ context.Context, _ string) (net.Conn, error) {
	return nil, errors.New("dial failed")
}

func (t *alwaysFailTransport) Handshake(_ context.Context, conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (t *alwaysFailTransport) Connect(_ context.Context, _ net.Conn, _ string, _ string) (net.Conn, error) {
	return nil, errors.New("connect failed")
}

func (t *alwaysFailTransport) Copy() Transporter {
	return t
}
