package chain

import (
	"context"
	"net"

	"forward/internal/connector"
	"forward/internal/dialer"
)

type Transport struct {
	dialer    dialer.Dialer
	connector connector.Connector
}

func NewTransport(d dialer.Dialer, c connector.Connector) *Transport {
	return &Transport{
		dialer:    d,
		connector: c,
	}
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return t.dialer.Dial(ctx, addr)
}

func (t *Transport) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if h, ok := t.dialer.(dialer.Handshaker); ok {
		return h.Handshake(ctx, conn)
	}
	return conn, nil
}

func (t *Transport) Connect(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error) {
	return t.connector.Connect(ctx, conn, network, address)
}

func (t *Transport) Copy() Transporter {
	if t == nil {
		return nil
	}
	return &Transport{
		dialer:    t.dialer,
		connector: t.connector,
	}
}
