package chain

import (
	"context"
	"net"
	"strings"
	"time"

	"forward/internal/config"
	ictx "forward/internal/ctx"
)

type defaultRoute struct {
	dialTimeout time.Duration
}

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

func (r defaultRoute) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	tr := ictx.TraceFromContext(ctx)
	if tr != nil && tr.Logger != nil {
		tr.Logger.Info("%s%s -> %s -> %s via %s", tr.Prefix(), tr.Src, tr.Local, address, RouteSummary(r))
		tr.Logger.Debug("%sdial start %s %s via %s", tr.Prefix(), strings.ToUpper(network), address, RouteSummary(r))
	}
	start := time.Now()

	timeout := r.dialTimeout
	if timeout <= 0 {
		timeout = config.DefaultDialTimeout
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := &net.Dialer{
		Timeout:  timeout,
		Resolver: defaultResolver,
	}
	conn, err := d.DialContext(ctx, network, address)
	if tr != nil && tr.Logger != nil {
		if err != nil {
			tr.Logger.Debug("%sdial error %s %s: %v (dur=%s)", tr.Prefix(), strings.ToUpper(network), address, err, time.Since(start))
		} else {
			tr.Logger.Debug("%sdial ok %s %s (dur=%s)", tr.Prefix(), strings.ToUpper(network), address, time.Since(start))
		}
	}
	return conn, err
}

func (r defaultRoute) Nodes() []*Node {
	return nil
}

// NewDefaultRoute 创建带有指定超时的默认直连路由
func NewDefaultRoute(dialTimeout time.Duration) Route {
	return defaultRoute{dialTimeout: dialTimeout}
}

type chainRoute struct {
	nodes       []*Node
	dialTimeout time.Duration
}

func NewRoute(nodes ...*Node) Route {
	return NewRouteWithTimeout(0, nodes...)
}

// NewRouteWithTimeout 创建带有指定超时的路由
func NewRouteWithTimeout(dialTimeout time.Duration, nodes ...*Node) Route {
	if len(nodes) == 0 {
		return defaultRoute{dialTimeout: dialTimeout}
	}
	r := &chainRoute{dialTimeout: dialTimeout}
	r.nodes = append(r.nodes, nodes...)
	return r
}

func (r *chainRoute) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if r == nil || len(r.nodes) == 0 {
		return defaultRoute{}.Dial(ctx, network, address)
	}

	tr := ictx.TraceFromContext(ctx)
	if tr != nil && tr.Logger != nil {
		tr.Logger.Info("%s%s -> %s -> %s via %s", tr.Prefix(), tr.Src, tr.Local, address, RouteSummary(r))
		tr.Logger.Debug("%sdial start %s %s via %s", tr.Prefix(), strings.ToUpper(network), address, RouteSummary(r))
	}

	labelNode := func(n *Node) string {
		if n == nil {
			return ""
		}
		if n.Display != "" {
			return n.Display
		}
		if n.Name != "" {
			return n.Name
		}
		return n.Addr
	}

	node := r.nodes[0]
	if tr != nil && tr.Logger != nil {
		tr.Logger.Debug("%sdial hop=0 node=%s addr=%s", tr.Prefix(), labelNode(node), node.Addr)
	}
	hopStart := time.Now()
	conn, err := node.Transport().Dial(ctx, node.Addr)
	if err != nil {
		if tr != nil && tr.Logger != nil {
			tr.Logger.Debug("%sdial hop=0 error node=%s addr=%s: %v (dur=%s)", tr.Prefix(), labelNode(node), node.Addr, err, time.Since(hopStart))
		}
		return nil, err
	}
	if tr != nil && tr.Logger != nil {
		tr.Logger.Debug("%sdial hop=0 ok node=%s addr=%s (dur=%s)", tr.Prefix(), labelNode(node), node.Addr, time.Since(hopStart))
		tr.Logger.Debug("%shandshake hop=0 node=%s", tr.Prefix(), labelNode(node))
	}
	hsStart := time.Now()
	hc, err := node.Transport().Handshake(ctx, conn)
	if err != nil {
		if tr != nil && tr.Logger != nil {
			tr.Logger.Debug("%shandshake hop=0 error node=%s: %v (dur=%s)", tr.Prefix(), labelNode(node), err, time.Since(hsStart))
		}
		conn.Close()
		return nil, err
	}
	if tr != nil && tr.Logger != nil {
		tr.Logger.Debug("%shandshake hop=0 ok node=%s (dur=%s)", tr.Prefix(), labelNode(node), time.Since(hsStart))
	}
	conn = hc

	prev := node
	for i, node := range r.nodes[1:] {
		hop := i + 1
		if tr != nil && tr.Logger != nil {
			tr.Logger.Debug("%sconnect hop=%d prev=%s -> node=%s addr=%s", tr.Prefix(), hop, labelNode(prev), labelNode(node), node.Addr)
		}
		csStart := time.Now()
		cc, err := prev.Transport().Connect(ctx, conn, "tcp", node.Addr)
		if err != nil {
			if tr != nil && tr.Logger != nil {
				tr.Logger.Debug("%sconnect hop=%d error prev=%s -> node=%s addr=%s: %v (dur=%s)", tr.Prefix(), hop, labelNode(prev), labelNode(node), node.Addr, err, time.Since(csStart))
			}
			conn.Close()
			return nil, err
		}
		if tr != nil && tr.Logger != nil {
			tr.Logger.Debug("%sconnect hop=%d ok prev=%s -> node=%s (dur=%s)", tr.Prefix(), hop, labelNode(prev), labelNode(node), time.Since(csStart))
			tr.Logger.Debug("%shandshake hop=%d node=%s", tr.Prefix(), hop, labelNode(node))
		}
		conn = cc
		hsStart := time.Now()
		cc, err = node.Transport().Handshake(ctx, conn)
		if err != nil {
			if tr != nil && tr.Logger != nil {
				tr.Logger.Debug("%shandshake hop=%d error node=%s: %v (dur=%s)", tr.Prefix(), hop, labelNode(node), err, time.Since(hsStart))
			}
			conn.Close()
			return nil, err
		}
		if tr != nil && tr.Logger != nil {
			tr.Logger.Debug("%shandshake hop=%d ok node=%s (dur=%s)", tr.Prefix(), hop, labelNode(node), time.Since(hsStart))
		}
		conn = cc

		prev = node
	}

	if tr != nil && tr.Logger != nil {
		tr.Logger.Debug("%sconnect dest prev=%s -> %s %s", tr.Prefix(), labelNode(prev), strings.ToUpper(network), address)
	}
	finalStart := time.Now()
	cc, err := prev.Transport().Connect(ctx, conn, network, address)
	if err != nil {
		if tr != nil && tr.Logger != nil {
			tr.Logger.Debug("%sconnect dest error prev=%s -> %s %s: %v (dur=%s)", tr.Prefix(), labelNode(prev), strings.ToUpper(network), address, err, time.Since(finalStart))
		}
		conn.Close()
		return nil, err
	}
	if tr != nil && tr.Logger != nil {
		tr.Logger.Debug("%sconnect dest ok prev=%s -> %s %s (dur=%s)", tr.Prefix(), labelNode(prev), strings.ToUpper(network), address, time.Since(finalStart))
		tr.Logger.Debug("%sdial done %s %s via %s", tr.Prefix(), strings.ToUpper(network), address, RouteSummary(r))
	}
	return cc, nil
}

func (r *chainRoute) Nodes() []*Node {
	if r == nil {
		return nil
	}
	return r.nodes
}
