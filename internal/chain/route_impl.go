package chain

import (
	"context"
	"net"
	"time"

	"forward/internal/config"
)

type defaultRoute struct{}

var defaultResolver *net.Resolver

func SetDefaultResolver(dnsServers []string) {
	if len(dnsServers) == 0 {
		return
	}
	defaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 5,
			}
			for _, server := range dnsServers {
				// 尝试解析 DNS 服务器地址，支持 host:port
				target := server
				if _, _, err := net.SplitHostPort(server); err != nil {
					// 默认为 DNS 端口
					target = net.JoinHostPort(server, "53")
				}
				conn, err := d.DialContext(ctx, "udp", target)
				if err == nil {
					return conn, nil
				}
				// 尝试 TCP
				conn, err = d.DialContext(ctx, "tcp", target)
				if err == nil {
					return conn, nil
				}
			}
			return nil, net.UnknownNetworkError("no valid dns server found")
		},
	}
}

func (defaultRoute) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	timeout := config.DefaultDialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := &net.Dialer{
		Timeout:  timeout,
		Resolver: defaultResolver,
	}
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
