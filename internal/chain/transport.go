package chain

import (
	"context"
	"net"
)

type Transporter interface {
	Dial(ctx context.Context, addr string) (net.Conn, error)
	Handshake(ctx context.Context, conn net.Conn) (net.Conn, error)
	Connect(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error)
	Copy() Transporter
}
