package udp

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

var errMissingAddr = errors.New("missing listen address")

type listenerMetadata struct {
	backlog        int
	readQueueSize  int
	readBufferSize int
	ttl            time.Duration
	keepalive      bool
	rateLimit      int
	allowCIDR      []*net.IPNet
	blockPrivate   bool
}

type Listener struct {
	addr    string
	logger  *logging.Logger
	options listener.Options
	md      listenerMetadata

	conn   net.PacketConn
	cqueue chan net.Conn
	pool   *udpsession.Pool[udpConnKey, *udpsession.Conn]
	closed chan struct{}
	errCh  chan error
	laddr  net.Addr

	limiter *rateLimiter

	mu sync.Mutex
}

type rateLimiter struct {
	mu        sync.Mutex
	counts    map[netip.Addr]int
	limit     int
	stop      chan struct{}
	closeOnce sync.Once
}

func newRateLimiter(limit int) *rateLimiter {
	rl := &rateLimiter{
		counts: make(map[netip.Addr]int),
		limit:  limit,
		stop:   make(chan struct{}),
	}
	go rl.run()
	return rl
}

func (rl *rateLimiter) allow(ip netip.Addr) bool {
	if rl.limit <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	n := rl.counts[ip]
	if n >= rl.limit {
		return false
	}
	rl.counts[ip] = n + 1
	return true
}

func (rl *rateLimiter) run() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			// Simple reset
			rl.counts = make(map[netip.Addr]int)
			rl.mu.Unlock()
		case <-rl.stop:
			return
		}
	}
}

func (rl *rateLimiter) close() {
	rl.closeOnce.Do(func() {
		close(rl.stop)
	})
}

func init() {
	registry.ListenerRegistry().Register("udp", NewListener)
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

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn != nil {
		return nil
	}

	laddr, err := net.ResolveUDPAddr("udp", l.addr)
	if err != nil {
		return listener.NewBindError(err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return listener.NewBindError(err)
	}

	l.conn = conn
	l.laddr = conn.LocalAddr()
	l.cqueue = make(chan net.Conn, l.md.backlog)
	l.closed = make(chan struct{})
	l.errCh = make(chan error, 1)
	l.pool = udpsession.NewPool[udpConnKey, *udpsession.Conn](l.md.ttl, l.logger, "UDP listener")
	if l.md.rateLimit > 0 {
		l.limiter = newRateLimiter(l.md.rateLimit)
	}

	go l.listenLoop()

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
	if l.laddr != nil {
		return l.laddr
	}
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return nil
}

func (l *Listener) Close() error {
	l.mu.Lock()
	conn := l.conn
	pool := l.pool
	closed := l.closed
	l.conn = nil
	l.pool = nil
	l.closed = nil
	l.mu.Unlock()

	if closed != nil {
		select {
		case <-closed:
		default:
			close(closed)
		}
	}
	if pool != nil {
		pool.Close()
	}
	if conn != nil {
		if l.logger != nil {
			l.logger.Info("Listener closed %s", conn.LocalAddr().String())
		}
		if l.limiter != nil {
			l.limiter.close()
		}
		return conn.Close()
	}
	if l.limiter != nil {
		l.limiter.close()
	}
	return nil
}

func (l *Listener) listenLoop() {
	for {
		select {
		case <-l.closed:
			return
		default:
		}

		buf := pool.GetWithSize(l.md.readBufferSize)
		n, raddr, err := l.conn.ReadFrom(buf)
		if err != nil {
			l.notifyErr(err)
			pool.Put(buf)
			return
		}
		udpAddr, ok := raddr.(*net.UDPAddr)
		if !ok || udpAddr == nil {
			pool.Put(buf)
			continue
		}

		// Access Control
		if !l.checkPacket(udpAddr) {
			pool.Put(buf)
			continue
		}

		// Rate limit check
		if l.limiter != nil {
			ip, ok := netipAddr(udpAddr)
			if !ok || !l.limiter.allow(ip) {
				pool.Put(buf)
				continue
			}
		}

		c := l.getConn(udpAddr)
		if c == nil {
			pool.Put(buf)
			continue
		}

		if err := c.WriteQueue(buf[:n]); err != nil {
			pool.Put(buf)
			if l.logger != nil {
				l.logger.Warn("UDP listener discarded packet from %s: %v", udpAddr.String(), err)
			}
		}
	}
}

func (l *Listener) getConn(raddr *net.UDPAddr) *udpsession.Conn {
	if raddr == nil {
		return nil
	}
	remote, ok := netipAddrPort(raddr)
	if !ok {
		return nil
	}
	key := udpConnKey{remote: remote}
	if c, ok := l.pool.Get(key); ok && !c.IsClosed() {
		return c
	}

	c := udpsession.NewConn(l.conn, l.Addr(), raddr, l.md.readQueueSize, l.md.keepalive)
	select {
	case l.cqueue <- c:
		l.pool.Set(key, c)
		return c
	default:
		c.Close()
		if l.logger != nil {
			l.logger.Warn("UDP listener connection queue full, client %s discarded", raddr.String())
		}
		return nil
	}
}

func (l *Listener) notifyErr(err error) {
	if err == nil {
		return
	}
	select {
	case l.errCh <- err:
	default:
	}
	close(l.errCh)
}

func (l *Listener) parseMetadata(md metadata.Metadata) {
	l.md.backlog = defaultBacklog
	l.md.readQueueSize = defaultReadQueueSize
	l.md.readBufferSize = config.DefaultBufferSize
	l.md.ttl = config.DefaultUDPIdleTimeout
	l.md.keepalive = true

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
	if v := metadata.IntValue(md.Get("rate_limit")); v > 0 {
		l.md.rateLimit = v
	}
	if v := metadata.StringValue(md.Get("allow_cidr")); v != "" {
		for _, s := range strings.Split(v, ",") {
			if _, ipnet, err := net.ParseCIDR(strings.TrimSpace(s)); err == nil {
				l.md.allowCIDR = append(l.md.allowCIDR, ipnet)
			}
		}
	}
	if v := md.Get("udp_block_private"); v != nil {
		l.md.blockPrivate = metadata.BoolValue(v)
	} else {
		l.md.blockPrivate = true // Default to true
	}
}

func (l *Listener) checkPacket(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	ip := addr.IP
	if ip == nil {
		return false
	}

	if l.md.blockPrivate && isReservedIP(ip) {
		return false
	}

	if len(l.md.allowCIDR) > 0 {
		allowed := false
		for _, ipnet := range l.md.allowCIDR {
			if ipnet.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	return true
}

// isReservedIP 检查是否为保留 IP（私有、loopback、link-local、CGNAT 等）
func isReservedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		isCGNAT(ip)
}

// isCGNAT 检查是否为 CGNAT 地址 (100.64.0.0/10)
func isCGNAT(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 100 && (ip4[1]&0xC0) == 64
	}
	return false
}

func netipAddr(addr *net.UDPAddr) (netip.Addr, bool) {
	if addr == nil {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func netipAddrPort(addr *net.UDPAddr) (netip.AddrPort, bool) {
	ip, ok := netipAddr(addr)
	if !ok || addr == nil || addr.Port < 0 || addr.Port > 65535 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, uint16(addr.Port)), true
}

type udpConnKey struct {
	remote netip.AddrPort
}
