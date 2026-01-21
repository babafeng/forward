package chain

import (
	"context"
	"net"
	"time"

	"forward/internal/config"
)

type defaultRoute struct{}

func (defaultRoute) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	timeout := config.DefaultDialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, address)
}

func (defaultRoute) Nodes() []*Node {
	return nil
}

type chainRoute struct {
	nodes []*Node
}

func NewRoute(nodes ...*Node) Route {
	if len(nodes) == 0 {
		return defaultRoute{}
	}
	r := &chainRoute{}
	r.nodes = append(r.nodes, nodes...)
	return r
}

func (r *chainRoute) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if r == nil || len(r.nodes) == 0 {
		return defaultRoute{}.Dial(ctx, network, address)
	}

	node := r.nodes[0]
	conn, err := node.Transport().Dial(ctx, node.Addr)
	if err != nil {
		return nil, err
	}
	hc, err := node.Transport().Handshake(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn = hc

	prev := node
	for _, node = range r.nodes[1:] {
		cc, err := prev.Transport().Connect(ctx, conn, "tcp", node.Addr)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = cc

		cc, err = node.Transport().Handshake(ctx, conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = cc

		prev = node
	}

	cc, err := prev.Transport().Connect(ctx, conn, network, address)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cc, nil
}

func (r *chainRoute) Nodes() []*Node {
	if r == nil {
		return nil
	}
	return r.nodes
}
