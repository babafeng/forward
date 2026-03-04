package chain

import (
	"context"
	"net"
	"time"

	"forward/internal/connector"
	"forward/internal/dialer"
)

type Transport struct {
	dialer    dialer.Dialer
	connector connector.Connector
	pool      *DialPool
}

func NewTransport(d dialer.Dialer, c connector.Connector) *Transport {
	return &Transport{
		dialer:    d,
		connector: c,
	}
}

// NewTransportWithPool creates a Transport with a pre-warming connection pool.
// The pool eagerly maintains handshaked connections to addr so that subsequent
// Dial calls can skip TCP+TLS establishment (~3 RTT saving).
func NewTransportWithPool(d dialer.Dialer, c connector.Connector, addr string) *Transport {
	return &Transport{
		dialer:    d,
		connector: c,
		pool:      NewDialPool(d, addr, 2, 90*time.Second),
	}
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if t.pool != nil {
		return t.pool.Get(ctx)
	}
	return t.dialer.Dial(ctx, addr)
}

func (t *Transport) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	// If the connection came from the pool it is already handshaked.
	if IsPooled(conn) {
		return UnwrapPooled(conn), nil
	}
	if h, ok := t.dialer.(dialer.Handshaker); ok {
		return h.Handshake(ctx, conn)
	}
	return conn, nil
}

func (t *Transport) Connect(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error) {
	return t.connector.Connect(ctx, conn, network, address)
}

// Close releases resources held by the transport (e.g. the dial pool).
func (t *Transport) Close() error {
	if t.pool != nil {
		t.pool.Close()
	}
	return nil
}

func (t *Transport) Copy() Transporter {
	if t == nil {
		return nil
	}
	return &Transport{
		dialer:    t.dialer,
		connector: t.connector,
		// pool is intentionally NOT copied – it belongs to the original
	}
}
