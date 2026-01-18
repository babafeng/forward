package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"forward/internal/config"
	"forward/internal/dialer"
	"forward/internal/endpoint"
	socks5util "forward/internal/utils/socks5"
)

const (
	verSocks5 = 0x05

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xff

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03
)

type Dialer struct {
	forward endpoint.Endpoint

	username string
	password string

	// Timeout is used when ctx has no deadline.
	Timeout time.Duration
	base    dialer.Dialer
}

func New(cfg config.Config) (*Dialer, error) {
	forward := *cfg.Forward
	scheme := strings.ToLower(forward.Scheme)
	if scheme != "socks5" && scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported forward scheme: %s", forward.Scheme)
	}
	user, pass, _ := forward.UserPass()
	return &Dialer{
		forward:  forward,
		username: user,
		password: pass,
		Timeout:  cfg.DialTimeout,
		base:     dialer.NewDirect(cfg),
	}, nil
}

func (d *Dialer) SetBase(base dialer.Dialer) {
	if base == nil {
		return
	}
	d.base = base
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	switch {
	case strings.HasPrefix(network, "tcp"):
		return d.dialTCP(ctx, address)
	case strings.HasPrefix(network, "udp"):
		return d.dialUDP(ctx, address)
	default:
		return nil, fmt.Errorf("socks5: unsupported network: %s", network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	if !strings.HasPrefix(network, "udp") {
		return nil, fmt.Errorf("socks5: unsupported packet network: %s", network)
	}
	return d.dialPacket(ctx, address)
}

func (d *Dialer) dialTCP(ctx context.Context, target string) (net.Conn, error) {
	tcpConn, err := d.dialForwardTCP(ctx)
	if err != nil {
		return nil, err
	}

	if err := d.handshake(ctx, tcpConn); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}

	host, port, err := splitHostPort(target)
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	if err := d.sendRequest(ctx, tcpConn, cmdConnect, host, port); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}

	_ = tcpConn.SetDeadline(time.Time{})

	return tcpConn, nil
}

func (d *Dialer) dialForwardTCP(ctx context.Context) (net.Conn, error) {
	return d.base.DialContext(ctx, "tcp", d.forward.Address())
}

func (d *Dialer) handshake(ctx context.Context, conn net.Conn) error {
	defer conn.SetDeadline(time.Time{})

	deadline := deadlineFromContext(ctx, d.Timeout)
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	methods := []byte{methodNoAuth}
	if d.username != "" || d.password != "" {
		methods = append(methods, methodUserPass)
	}
	greet := []byte{verSocks5, byte(len(methods))}
	greet = append(greet, methods...)
	if _, err := conn.Write(greet); err != nil {
		return fmt.Errorf("socks5: greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: greeting response: %w", err)
	}
	if resp[0] != verSocks5 {
		return fmt.Errorf("socks5: unexpected version: %d", resp[0])
	}
	switch resp[1] {
	case methodNoAuth:
		return nil
	case methodUserPass:
		return d.authUserPass(conn)
	case methodNoAcceptable:
		return fmt.Errorf("socks5: no acceptable authentication method")
	default:
		return fmt.Errorf("socks5: unsupported auth method selected by server: 0x%02x", resp[1])
	}
}

func (d *Dialer) authUserPass(conn net.Conn) error {
	uname := d.username
	pass := d.password
	if len(uname) > 255 || len(pass) > 255 {
		return fmt.Errorf("socks5: username/password too long")
	}

	// RFC 1929
	req := make([]byte, 0, 3+len(uname)+len(pass))
	req = append(req, 0x01, byte(len(uname)))
	req = append(req, []byte(uname)...)
	req = append(req, byte(len(pass)))
	req = append(req, []byte(pass)...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5: auth request: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: auth response: %w", err)
	}
	if resp[0] != 0x01 {
		return fmt.Errorf("socks5: unexpected auth version: %d", resp[0])
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5: authentication failed (status=0x%02x)", resp[1])
	}
	return nil
}

func (d *Dialer) sendRequest(ctx context.Context, conn net.Conn, cmd byte, host string, port int) error {
	defer conn.SetDeadline(time.Time{})

	deadline := deadlineFromContext(ctx, d.Timeout)
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	addr, err := socks5util.EncodeAddr(host, port)
	if err != nil {
		return err
	}

	req := make([]byte, 0, 3+len(addr))
	req = append(req, verSocks5, cmd, 0x00)
	req = append(req, addr...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5: request write: %w", err)
	}

	rep, _, _, err := readReply(conn)
	if err != nil {
		return err
	}
	if rep != 0x00 {
		return fmt.Errorf("socks5: request failed: %s", replyMessage(rep))
	}
	return nil
}

func deadlineFromContext(ctx context.Context, fallback time.Duration) time.Time {
	if ctx == nil {
		return time.Time{}
	}
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	if fallback > 0 {
		return time.Now().Add(fallback)
	}
	return time.Time{}
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q in %q", portStr, addr)
	}
	return host, port, nil
}

func readReply(r io.Reader) (rep byte, host string, port int, err error) {
	head := make([]byte, 4)
	if _, err = io.ReadFull(r, head); err != nil {
		return 0, "", 0, fmt.Errorf("socks5: reply read header: %w", err)
	}
	if head[0] != verSocks5 {
		return 0, "", 0, fmt.Errorf("socks5: unexpected reply version: %d", head[0])
	}
	rep = head[1]
	atyp := head[3]

	host, port, err = readAddrPort(r, atyp)
	if err != nil {
		return 0, "", 0, err
	}
	return rep, host, port, nil
}

func readAddrPort(r io.Reader, atyp byte) (host string, port int, err error) {
	switch atyp {
	case socks5util.AtypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, fmt.Errorf("socks5: read ipv4: %w", err)
		}
		host = net.IP(b).String()
	case socks5util.AtypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, fmt.Errorf("socks5: read ipv6: %w", err)
		}
		host = net.IP(b).String()
	case socks5util.AtypDomain:
		lb := []byte{0}
		if _, err := io.ReadFull(r, lb); err != nil {
			return "", 0, fmt.Errorf("socks5: read domain length: %w", err)
		}
		l := int(lb[0])
		if l == 0 {
			return "", 0, fmt.Errorf("socks5: empty domain")
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, fmt.Errorf("socks5: read domain: %w", err)
		}
		host = string(b)
	default:
		return "", 0, fmt.Errorf("socks5: unknown address type: 0x%02x", atyp)
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(r, pb); err != nil {
		return "", 0, fmt.Errorf("socks5: read port: %w", err)
	}
	port = int(binary.BigEndian.Uint16(pb))
	return host, port, nil
}

func replyMessage(rep byte) string {
	switch rep {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown error (0x%02x)", rep)
	}
}

func localIPFromConn(conn net.Conn) net.IP {
	ta, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || ta == nil {
		return nil
	}
	if ta.IP == nil {
		return nil
	}
	ip := make(net.IP, len(ta.IP))
	copy(ip, ta.IP)
	return ip
}

type udpAddr struct {
	network string
	addr    string
}

func (a udpAddr) Network() string { return a.network }
func (a udpAddr) String() string  { return a.addr }

type UDPConn struct {
	control net.Conn
	udp     *net.UDPConn

	relay *net.UDPAddr

	destHost string
	destPort int
	prefix   []byte
}

func (d *Dialer) dialUDP(ctx context.Context, target string) (net.Conn, error) {
	control, err := d.dialForwardTCP(ctx)
	if err != nil {
		return nil, err
	}
	if err := d.handshake(ctx, control); err != nil {
		_ = control.Close()
		return nil, err
	}

	destHost, destPort, err := splitHostPort(target)
	if err != nil {
		_ = control.Close()
		return nil, err
	}

	localIP := localIPFromConn(control)
	udpSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		_ = control.Close()
		return nil, fmt.Errorf("socks5: listen udp: %w", err)
	}
	udpLocal := udpSock.LocalAddr().(*net.UDPAddr)

	relay, err := d.udpAssociate(ctx, control, udpLocal)
	if err != nil {
		_ = udpSock.Close()
		_ = control.Close()
		return nil, err
	}

	if relay.IP == nil || relay.IP.IsUnspecified() {
		relay.IP = proxyRemoteIP(control)
	}

	prefix, err := buildUDPPrefix(destHost, destPort)
	if err != nil {
		_ = udpSock.Close()
		_ = control.Close()
		return nil, err
	}

	_ = control.SetDeadline(time.Time{})

	return &UDPConn{
		control:  control,
		udp:      udpSock,
		relay:    relay,
		destHost: destHost,
		destPort: destPort,
		prefix:   prefix,
	}, nil
}

func (d *Dialer) dialPacket(ctx context.Context, localAddr string) (net.PacketConn, error) {
	control, err := d.dialForwardTCP(ctx)
	if err != nil {
		return nil, err
	}
	if err := d.handshake(ctx, control); err != nil {
		_ = control.Close()
		return nil, err
	}

	localIP := localIPFromConn(control)
	udpLocal := &net.UDPAddr{IP: localIP, Port: 0}
	if localAddr != "" {
		if host, portStr, err := net.SplitHostPort(localAddr); err == nil {
			port, _ := strconv.Atoi(portStr)
			if host != "" {
				if ip := net.ParseIP(host); ip != nil {
					udpLocal.IP = ip
				}
			}
			udpLocal.Port = port
		}
	}

	udpSock, err := net.ListenUDP("udp", udpLocal)
	if err != nil {
		_ = control.Close()
		return nil, fmt.Errorf("socks5: listen udp: %w", err)
	}

	relay, err := d.udpAssociate(ctx, control, udpSock.LocalAddr().(*net.UDPAddr))
	if err != nil {
		_ = udpSock.Close()
		_ = control.Close()
		return nil, err
	}

	if relay.IP == nil || relay.IP.IsUnspecified() {
		relay.IP = proxyRemoteIP(control)
	}

	_ = control.SetDeadline(time.Time{})

	return &udpPacketConn{
		control: control,
		udp:     udpSock,
		relay:   relay,
	}, nil
}

func proxyRemoteIP(control net.Conn) net.IP {
	ra, ok := control.RemoteAddr().(*net.TCPAddr)
	if ok && ra != nil && ra.IP != nil {
		ip := make(net.IP, len(ra.IP))
		copy(ip, ra.IP)
		return ip
	}
	// Fall back to resolving proxy host string.
	host, _, err := net.SplitHostPort(control.RemoteAddr().String())
	if err == nil {
		ip := net.ParseIP(host)
		if ip != nil {
			return ip
		}
	}
	return nil
}

func (d *Dialer) udpAssociate(ctx context.Context, control net.Conn, local *net.UDPAddr) (*net.UDPAddr, error) {
	defer control.SetDeadline(time.Time{})

	deadline := deadlineFromContext(ctx, d.Timeout)
	if !deadline.IsZero() {
		_ = control.SetDeadline(deadline)
	}

	host := local.IP.String()
	if local.IP == nil || local.IP.IsUnspecified() {
		if isIPv6Conn(control) {
			host = "::"
		} else {
			host = "0.0.0.0"
		}
	}

	reqAddr, err := socks5util.EncodeAddr(host, local.Port)
	if err != nil {
		return nil, err
	}

	req := make([]byte, 0, 3+len(reqAddr))
	req = append(req, verSocks5, cmdUDPAssociate, 0x00)
	req = append(req, reqAddr...)

	if _, err := control.Write(req); err != nil {
		return nil, fmt.Errorf("socks5: udp associate write: %w", err)
	}

	rep, host, port, err := readReply(control)
	if err != nil {
		return nil, err
	}
	if rep != 0x00 {
		return nil, fmt.Errorf("socks5: udp associate failed: %s", replyMessage(rep))
	}

	relayAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("socks5: resolve udp relay %s:%d: %w", host, port, err)
	}
	return relayAddr, nil
}

func isIPv6Conn(c net.Conn) bool {
	la, ok := c.LocalAddr().(*net.TCPAddr)
	if ok && la != nil && la.IP != nil {
		return la.IP.To4() == nil
	}
	return false
}

func buildUDPPrefix(destHost string, destPort int) ([]byte, error) {
	addr, err := socks5util.EncodeAddr(destHost, destPort)
	if err != nil {
		return nil, err
	}
	p := make([]byte, 0, 3+len(addr))
	p = append(p, 0x00, 0x00, 0x00) // RSV, RSV, FRAG(0)
	p = append(p, addr...)          // ATYP + ADDR + PORT
	return p, nil
}

func (c *UDPConn) Read(p []byte) (int, error) {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			return 0, err
		}
		if !udpAddrEqual(from, c.relay) {
			continue
		}
		payload, err := parseUDPDatagram(buf[:n])
		if err != nil {
			continue
		}
		if len(payload) > len(p) {
			copy(p, payload[:len(p)])
			return len(p), nil
		}
		copy(p, payload)
		return len(payload), nil
	}
}

func (c *UDPConn) Write(p []byte) (int, error) {
	buf := make([]byte, 0, len(c.prefix)+len(p))
	buf = append(buf, c.prefix...)
	buf = append(buf, p...)

	_, err := c.udp.WriteToUDP(buf, c.relay)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *UDPConn) Close() error {
	var first error
	if err := c.udp.Close(); err != nil {
		first = err
	}
	if err := c.control.Close(); err != nil && first == nil {
		first = err
	}
	return first
}

func (c *UDPConn) LocalAddr() net.Addr { return c.udp.LocalAddr() }
func (c *UDPConn) RemoteAddr() net.Addr {
	return udpAddr{network: "udp", addr: net.JoinHostPort(c.destHost, strconv.Itoa(c.destPort))}
}
func (c *UDPConn) SetDeadline(t time.Time) error {
	if err := c.udp.SetDeadline(t); err != nil {
		return err
	}
	return c.control.SetDeadline(t)
}
func (c *UDPConn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *UDPConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

type udpPacketConn struct {
	control net.Conn
	udp     *net.UDPConn

	relay *net.UDPAddr
}

func (c *udpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, err
		}
		if !udpAddrEqual(from, c.relay) {
			continue
		}
		host, port, payload, err := parseUDPDatagramWithAddr(buf[:n])
		if err != nil {
			continue
		}
		addr := addrFromHostPort(host, port)
		if len(payload) > len(p) {
			copy(p, payload[:len(p)])
			return len(p), addr, nil
		}
		copy(p, payload)
		return len(payload), addr, nil
	}
}

func (c *udpPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	host, port, err := hostPortFromAddr(addr)
	if err != nil {
		return 0, err
	}
	prefix, err := buildUDPPrefix(host, port)
	if err != nil {
		return 0, err
	}
	buf := make([]byte, 0, len(prefix)+len(p))
	buf = append(buf, prefix...)
	buf = append(buf, p...)

	_, err = c.udp.WriteToUDP(buf, c.relay)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *udpPacketConn) Close() error {
	var first error
	if err := c.udp.Close(); err != nil {
		first = err
	}
	if err := c.control.Close(); err != nil && first == nil {
		first = err
	}
	return first
}

func (c *udpPacketConn) LocalAddr() net.Addr { return c.udp.LocalAddr() }

func (c *udpPacketConn) SetDeadline(t time.Time) error {
	if err := c.udp.SetDeadline(t); err != nil {
		return err
	}
	return c.control.SetDeadline(t)
}

func (c *udpPacketConn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *udpPacketConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

func hostPortFromAddr(addr net.Addr) (string, int, error) {
	if addr == nil {
		return "", 0, fmt.Errorf("socks5: missing udp address")
	}
	if ua, ok := addr.(*net.UDPAddr); ok && ua.IP != nil && !ua.IP.IsUnspecified() {
		return ua.IP.String(), ua.Port, nil
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0, fmt.Errorf("socks5: invalid udp address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("socks5: invalid udp port: %w", err)
	}
	return host, port, nil
}

func addrFromHostPort(host string, port int) net.Addr {
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}
	}
	return udpAddr{network: "udp", addr: net.JoinHostPort(host, strconv.Itoa(port))}
}

func parseUDPDatagram(b []byte) ([]byte, error) {
	_, _, payload, err := parseUDPDatagramWithAddr(b)
	return payload, err
}

func parseUDPDatagramWithAddr(b []byte) (string, int, []byte, error) {
	if len(b) < 4 {
		return "", 0, nil, errors.New("short udp datagram")
	}
	if b[0] != 0x00 || b[1] != 0x00 {
		return "", 0, nil, errors.New("bad rsv")
	}
	if b[2] != 0x00 {
		return "", 0, nil, errors.New("fragmentation not supported")
	}
	atyp := b[3]
	off := 4
	switch atyp {
	case socks5util.AtypIPv4:
		if len(b) < off+4+2 {
			return "", 0, nil, errors.New("short ipv4 header")
		}
		host := net.IP(b[off : off+4]).String()
		off += 4 + 2
		port := int(binary.BigEndian.Uint16(b[off-2 : off]))
		return host, port, b[off:], nil
	case socks5util.AtypIPv6:
		if len(b) < off+16+2 {
			return "", 0, nil, errors.New("short ipv6 header")
		}
		host := net.IP(b[off : off+16]).String()
		off += 16 + 2
		port := int(binary.BigEndian.Uint16(b[off-2 : off]))
		return host, port, b[off:], nil
	case socks5util.AtypDomain:
		if len(b) < off+1 {
			return "", 0, nil, errors.New("short domain header")
		}
		l := int(b[off])
		off++
		if len(b) < off+l+2 {
			return "", 0, nil, errors.New("short domain header")
		}
		host := string(b[off : off+l])
		off += l + 2
		port := int(binary.BigEndian.Uint16(b[off-2 : off]))
		return host, port, b[off:], nil
	default:
		return "", 0, nil, errors.New("unknown atyp")
	}
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Port != b.Port {
		return false
	}
	if a.IP == nil && b.IP == nil {
		return true
	}
	if a.IP == nil || b.IP == nil {
		return false
	}
	return a.IP.Equal(b.IP)
}
