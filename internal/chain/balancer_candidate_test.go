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
	}, time.Hour, 30*time.Millisecond)
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
	}, time.Hour, 30*time.Millisecond)

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
	}, time.Hour, 30*time.Millisecond)
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
