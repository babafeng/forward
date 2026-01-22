package chain

import (
	"context"
	"net"
)

type Route interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
	Nodes() []*Node
}
