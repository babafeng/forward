package hysteria2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	hyclient "github.com/apernet/hysteria/core/v2/client"

	"forward/internal/connector"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	_ = registry.ConnectorRegistry().Register("hysteria2", NewConnector)
	_ = registry.ConnectorRegistry().Register("hy2", NewConnector)
}

type clientProvider interface {
	HYClient() hyclient.Client
}

type Connector struct {
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Connector{options: options}
}

func (c *Connector) Init(_ metadata.Metadata) error {
	return nil
}

func (c *Connector) Connect(ctx context.Context, conn net.Conn, network, address string, _ ...connector.ConnectOption) (net.Conn, error) {
	provider, ok := conn.(clientProvider)
	if !ok {
		return nil, fmt.Errorf("hysteria2 connector requires hysteria2 dialer connection")
	}
	client := provider.HYClient()
	if client == nil {
		return nil, fmt.Errorf("hysteria2 connector missing client")
	}

	switch {
	case isTCP(network):
		return client.TCP(address)
	case isUDP(network):
		if _, _, err := net.SplitHostPort(address); err != nil {
			return nil, fmt.Errorf("hysteria2 udp invalid target %q: %w", address, err)
		}
		huc, err := client.UDP()
		if err != nil {
			return nil, err
		}
		return newHyUDPNetConn(huc, address, conn.LocalAddr()), nil
	default:
		return nil, fmt.Errorf("hysteria2 connector supports tcp/udp only")
	}
}

func isUDP(network string) bool {
	network = strings.ToLower(strings.TrimSpace(network))
	return strings.HasPrefix(network, "udp")
}

func isTCP(network string) bool {
	network = strings.ToLower(strings.TrimSpace(network))
	return strings.HasPrefix(network, "tcp")
}

type udpPacket struct {
	data []byte
	err  error
}

type hyUDPNetConn struct {
	conn    hyclient.HyUDPConn
	target  string
	targetN string
	local   net.Addr

	recvCh   chan udpPacket
	closeCh  chan struct{}
	closeMux sync.Once

	deadlineMux   sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func newHyUDPNetConn(conn hyclient.HyUDPConn, target string, local net.Addr) *hyUDPNetConn {
	c := &hyUDPNetConn{
		conn:    conn,
		target:  target,
		targetN: normalizeUDPAddr(target),
		local:   local,
		recvCh:  make(chan udpPacket, 64),
		closeCh: make(chan struct{}),
	}
	go c.receiveLoop()
	return c
}

func (c *hyUDPNetConn) Read(b []byte) (int, error) {
	for {
		var (
			timer  *time.Timer
			timerC <-chan time.Time
		)
		deadline := c.readDeadlineValue()
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timerC = timer.C
		}

		select {
		case pkt := <-c.recvCh:
			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}
			if pkt.err != nil {
				return 0, pkt.err
			}
			n := copy(b, pkt.data)
			return n, nil
		case <-c.closeCh:
			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}
			return 0, net.ErrClosed
		case <-timerC:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *hyUDPNetConn) Write(b []byte) (int, error) {
	if c.target == "" {
		return 0, errors.New("hysteria2 udp missing target address")
	}
	if c.writeTimedOut() {
		return 0, os.ErrDeadlineExceeded
	}
	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	default:
	}
	if err := c.conn.Send(b, c.target); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *hyUDPNetConn) Close() error {
	var err error
	c.closeMux.Do(func() {
		close(c.closeCh)
		err = c.conn.Close()
	})
	return err
}

func (c *hyUDPNetConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return &net.UDPAddr{}
}

func (c *hyUDPNetConn) RemoteAddr() net.Addr {
	addr, err := net.ResolveUDPAddr("udp", c.target)
	if err == nil {
		return addr
	}
	return udpAddr{network: "udp", addr: c.target}
}

func (c *hyUDPNetConn) SetDeadline(t time.Time) error {
	c.deadlineMux.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.deadlineMux.Unlock()
	return nil
}

func (c *hyUDPNetConn) SetReadDeadline(t time.Time) error {
	c.deadlineMux.Lock()
	c.readDeadline = t
	c.deadlineMux.Unlock()
	return nil
}

func (c *hyUDPNetConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMux.Lock()
	c.writeDeadline = t
	c.deadlineMux.Unlock()
	return nil
}

func (c *hyUDPNetConn) receiveLoop() {
	for {
		payload, addr, err := c.conn.Receive()
		if err != nil {
			select {
			case c.recvCh <- udpPacket{err: err}:
			case <-c.closeCh:
			}
			return
		}

		if c.targetN != "" {
			if normalizeUDPAddr(addr) != c.targetN {
				continue
			}
		}

		data := append([]byte(nil), payload...)
		select {
		case c.recvCh <- udpPacket{data: data}:
		case <-c.closeCh:
			return
		}
	}
}

func (c *hyUDPNetConn) readDeadlineValue() time.Time {
	c.deadlineMux.RLock()
	d := c.readDeadline
	c.deadlineMux.RUnlock()
	return d
}

func (c *hyUDPNetConn) writeTimedOut() bool {
	c.deadlineMux.RLock()
	d := c.writeDeadline
	c.deadlineMux.RUnlock()
	if d.IsZero() {
		return false
	}
	return !time.Now().Before(d)
}

func normalizeUDPAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.TrimSpace(strings.ToLower(addr))
	}
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	return net.JoinHostPort(host, port)
}

type udpAddr struct {
	network string
	addr    string
}

func (a udpAddr) Network() string { return a.network }
func (a udpAddr) String() string  { return a.addr }
