package tproxy

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"forward/base/logging"
	"forward/base/pool"
	"forward/internal/config"
	"forward/internal/listener"
	"forward/internal/listener/udpsession"
	"forward/internal/metadata"
	"forward/internal/registry"
)

const (
	defaultBacklog       = 128
	defaultReadQueueSize = 128
)

type listenerMetadata struct {
	backlog        int
	readQueueSize  int
	readBufferSize int
	ttl            time.Duration
	keepalive      bool
	enableTCP      bool
	enableUDP      bool
}

type Listener struct {
	addr    string
	logger  *logging.Logger
	options listener.Options
	md      listenerMetadata

	tcpLn net.Listener
	udpLn *net.UDPConn

	cqueue chan net.Conn
	pool   *udpsession.Pool[udpConnKey, *udpMetaConn]
	closed chan struct{}
	errCh  chan error
	laddr  net.Addr

	localIPs    map[netip.Addr]struct{}
	udpBindPort uint16

	mu      sync.Mutex
	errOnce sync.Once
}

func init() {
	registry.ListenerRegistry().Register("tproxy", NewListener)
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Listener{
		addr:    options.Addr,
		logger:  options.Logger,
		options: options,
	}
}

func (l *Listener) Init(md metadata.Metadata) error {
	l.parseMetadata(md)

	if l.addr == "" {
		return listener.NewBindError(errMissingAddr)
	}
	if !l.md.enableTCP && !l.md.enableUDP {
		return listener.NewBindError(errors.New("tproxy: network disabled"))
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed != nil {
		return nil
	}

	if l.md.enableTCP {
		ln, err := l.listenTCP(l.addr)
		if err != nil {
			return listener.NewBindError(err)
		}
		l.tcpLn = ln
		l.laddr = ln.Addr()
	}

	if l.md.enableUDP {
		pc, err := l.listenUDP(l.addr)
		if err != nil {
			if l.tcpLn != nil {
				_ = l.tcpLn.Close()
				l.tcpLn = nil
			}
			return listener.NewBindError(err)
		}
		l.udpLn = pc
		if l.laddr == nil {
			l.laddr = pc.LocalAddr()
		}
		l.pool = udpsession.NewPool[udpConnKey, *udpMetaConn](l.md.ttl, l.logger, "TPROXY UDP")
	}

	l.cqueue = make(chan net.Conn, l.md.backlog)
	l.closed = make(chan struct{})
	l.errCh = make(chan error, 1)
	l.cacheLocalTargets()

	if l.tcpLn != nil {
		go l.acceptTCP()
	}
	if l.udpLn != nil {
		go l.acceptUDP()
	}

	return nil
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.cqueue:
		return c, nil
	case <-l.closed:
		return nil, listener.ErrClosed
	case err := <-l.errCh:
		if err == nil {
			err = net.ErrClosed
		}
		return nil, listener.NewAcceptError(err)
	}
}

func (l *Listener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.laddr
}

func (l *Listener) Close() error {
	l.mu.Lock()
	tcpLn := l.tcpLn
	udpLn := l.udpLn
	pool := l.pool
	closed := l.closed
	errCh := l.errCh
	l.tcpLn = nil
	l.udpLn = nil
	l.pool = nil
	l.closed = nil
	l.errCh = nil
	l.mu.Unlock()

	if closed != nil {
		select {
		case <-closed:
		default:
			close(closed)
		}
	}
	if errCh != nil {
		l.errOnce.Do(func() {
			close(errCh)
		})
	}
	if pool != nil {
		pool.Close()
	}
	if tcpLn != nil {
		if l.logger != nil {
			l.logger.Info("Listener closed %s", tcpLn.Addr().String())
		}
		_ = tcpLn.Close()
	}
	if udpLn != nil {
		if l.logger != nil {
			l.logger.Info("Listener closed %s", udpLn.LocalAddr().String())
		}
		_ = udpLn.Close()
	}
	return nil
}

func (l *Listener) acceptTCP() {
	for {
		conn, err := l.tcpLn.Accept()
		if err != nil {
			l.notifyErr(err)
			return
		}
		orig := ""
		if conn.LocalAddr() != nil {
			orig = conn.LocalAddr().String()
		}
		md := metadata.New(map[string]any{
			metadata.KeyOriginalDst: orig,
			metadata.KeyNetwork:     "tcp",
		})
		tc := &tcpMetaConn{Conn: conn, md: md}
		select {
		case l.cqueue <- tc:
		default:
			_ = conn.Close()
			if l.logger != nil {
				l.logger.Warn("TPROXY TCP queue full, dropped %s", conn.RemoteAddr().String())
			}
		}
	}
}

func (l *Listener) acceptUDP() {
	for {
		select {
		case <-l.closed:
			return
		default:
		}

		buf := pool.GetWithSize(l.md.readBufferSize)
		n, raddr, dstAddr, err := readFromUDP(l.udpLn, buf)
		if err != nil {
			l.notifyErr(err)
			pool.Put(buf)
			return
		}

		c := l.getConn(raddr, dstAddr)
		if c == nil {
			pool.Put(buf)
			continue
		}
		if err := c.WriteQueue(buf[:n]); err != nil {
			pool.Put(buf)
			if l.logger != nil {
				l.logger.Warn("TPROXY UDP listener discarded packet from %s: %v", raddr.String(), err)
			}
		}
	}
}

func (l *Listener) getConn(raddr, dstAddr *net.UDPAddr) *udpMetaConn {
	if raddr == nil || dstAddr == nil {
		return nil
	}
	if l.shouldIgnoreUDP(dstAddr) {
		return nil
	}
	src, ok := netipAddrPort(raddr)
	if !ok {
		return nil
	}
	dst, ok := netipAddrPort(dstAddr)
	if !ok {
		return nil
	}
	key := udpConnKey{src: src, dst: dst}
	if c, ok := l.pool.Get(key); ok && !c.isClosed() {
		return c
	}

	uc := udpsession.NewConn(l.udpLn, dstAddr, raddr, l.md.readQueueSize, l.md.keepalive)
	md := metadata.New(map[string]any{
		metadata.KeyOriginalDst: dstAddr.String(),
		metadata.KeyNetwork:     "udp",
	})
	tc := &udpMetaConn{Conn: uc, md: md}

	select {
	case l.cqueue <- tc:
		l.pool.Set(key, tc)
		return tc
	default:
		_ = uc.Close()
		if l.logger != nil {
			l.logger.Warn("TPROXY UDP connection queue full, client %s discarded", raddr.String())
		}
		return nil
	}
}

func (l *Listener) notifyErr(err error) {
	if err == nil {
		return
	}
	l.errOnce.Do(func() {
		select {
		case l.errCh <- err:
		default:
		}
		close(l.errCh)
	})
}

func (l *Listener) parseMetadata(md metadata.Metadata) {
	l.md.backlog = defaultBacklog
	l.md.readQueueSize = defaultReadQueueSize
	l.md.readBufferSize = config.DefaultBufferSize
	l.md.ttl = config.DefaultUDPIdleTimeout
	l.md.keepalive = true
	l.md.enableTCP = true
	l.md.enableUDP = true

	if md == nil {
		return
	}
	if v := metadata.IntValue(md.Get("backlog")); v > 0 {
		l.md.backlog = v
	}
	if v := metadata.IntValue(md.Get("read_queue")); v > 0 {
		l.md.readQueueSize = v
	}
	if v := metadata.IntValue(md.Get("read_buffer")); v > 0 {
		l.md.readBufferSize = v
	}
	if v := metadata.DurationValue(md.Get("udp_idle")); v > 0 {
		l.md.ttl = v
	}
	if v := metadata.DurationValue(md.Get("ttl")); v > 0 {
		l.md.ttl = v
	}
	if v := md.Get("keepalive"); v != nil {
		l.md.keepalive = metadata.BoolValue(v)
	}
	if v := metadata.StringValue(md.Get("network")); v != "" {
		l.md.enableTCP = false
		l.md.enableUDP = false
		for _, s := range strings.Split(v, ",") {
			switch strings.ToLower(strings.TrimSpace(s)) {
			case "tcp":
				l.md.enableTCP = true
			case "udp":
				l.md.enableUDP = true
			}
		}
	}
}

func (l *Listener) cacheLocalTargets() {
	localIPs := make(map[netip.Addr]struct{})
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if ip, ok := netipAddrFromIP(v.IP); ok {
					localIPs[ip] = struct{}{}
				}
			case *net.IPAddr:
				if ip, ok := netipAddrFromIP(v.IP); ok {
					localIPs[ip] = struct{}{}
				}
			}
		}
	}
	if l.udpLn != nil {
		if udpAddr, ok := l.udpLn.LocalAddr().(*net.UDPAddr); ok && udpAddr != nil {
			l.udpBindPort = uint16(udpAddr.Port)
			if ip, ok := netipAddrFromIP(udpAddr.IP); ok {
				localIPs[ip] = struct{}{}
			}
		}
	}
	l.localIPs = localIPs
}

func (l *Listener) shouldIgnoreUDP(dstAddr *net.UDPAddr) bool {
	if l == nil || dstAddr == nil || l.udpBindPort == 0 {
		return false
	}
	if dstAddr.Port != int(l.udpBindPort) {
		return false
	}
	ip, ok := netipAddrFromIP(dstAddr.IP)
	if !ok {
		return false
	}
	_, ok = l.localIPs[ip]
	return ok
}

type tcpMetaConn struct {
	net.Conn
	md metadata.Metadata
}

func (c *tcpMetaConn) Metadata() metadata.Metadata {
	return c.md
}

type udpMetaConn struct {
	*udpsession.Conn
	md metadata.Metadata
}

func (c *udpMetaConn) Metadata() metadata.Metadata {
	return c.md
}

func (c *udpMetaConn) isClosed() bool {
	if c == nil || c.Conn == nil {
		return true
	}
	return c.Conn.IsClosed()
}

func (c *udpMetaConn) WriteQueue(b []byte) error {
	if c == nil || c.Conn == nil {
		return errors.New("tproxy: udp conn required")
	}
	return c.Conn.WriteQueue(b)
}

type udpConnKey struct {
	src netip.AddrPort
	dst netip.AddrPort
}

func netipAddrPort(addr *net.UDPAddr) (netip.AddrPort, bool) {
	if addr == nil || addr.Port < 0 || addr.Port > 65535 {
		return netip.AddrPort{}, false
	}
	ip, ok := netipAddrFromIP(addr.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, uint16(addr.Port)), true
}

func netipAddrFromIP(ip net.IP) (netip.Addr, bool) {
	if len(ip) == 0 {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), !addr.Unmap().IsUnspecified()
}

var errMissingAddr = errors.New("missing listen address")
