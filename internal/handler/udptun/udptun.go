package udptun

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	socks5util "forward/base/utils/socks5"
)

const (
	udpFragTunnel = 0xff
	maxUDPLength  = 65535
)

type udpTunConn struct {
	net.Conn
	taddr net.Addr
	mu    sync.Mutex
}

func ClientConn(c net.Conn, targetAddr net.Addr) net.Conn {
	return &udpTunConn{
		Conn:  c,
		taddr: targetAddr,
	}
}

func ClientPacketConn(c net.Conn) net.PacketConn {
	return &udpTunConn{Conn: c}
}

func ServerConn(c net.Conn) net.PacketConn {
	return &udpTunConn{Conn: c}
}

func (c *udpTunConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	header := make([]byte, 3)
	if _, err = io.ReadFull(c.Conn, header); err != nil {
		return 0, nil, err
	}
	dlen := int(binary.BigEndian.Uint16(header[:2]))
	if dlen <= 0 || dlen > maxUDPLength {
		return 0, nil, errors.New("udptun: invalid datagram length")
	}
	if header[2] != udpFragTunnel {
		return 0, nil, errors.New("udptun: invalid fragment")
	}
	atyp := []byte{0}
	if _, err = io.ReadFull(c.Conn, atyp); err != nil {
		return 0, nil, err
	}
	host, port, err := socks5util.ReadAddr(c.Conn, atyp[0])
	if err != nil {
		return 0, nil, err
	}
	payload := make([]byte, dlen)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return 0, nil, err
	}
	n = copy(b, payload)
	addr, _ = net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	return n, addr, nil
}

func (c *udpTunConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *udpTunConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errors.New("udptun: missing addr")
	}
	if len(b) > maxUDPLength {
		return 0, errors.New("udptun: payload too large")
	}
	host, port, err := splitHostPort(addr.String())
	if err != nil {
		return 0, err
	}
	enc, err := socks5util.EncodeAddr(host, port)
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[:2], uint16(len(b)))
	header[2] = udpFragTunnel
	if _, err := c.Conn.Write(header); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(enc); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *udpTunConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.taddr)
}

func (c *udpTunConn) LocalAddr() net.Addr  { return c.Conn.LocalAddr() }
func (c *udpTunConn) RemoteAddr() net.Addr { return c.Conn.RemoteAddr() }
func (c *udpTunConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}
func (c *udpTunConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}
func (c *udpTunConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return strings.Trim(host, "[]"), port, nil
}
