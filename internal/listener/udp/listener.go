package udp

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"forward/base/logging"
	"forward/base/pool"
	"forward/internal/config"
	"forward/internal/listener"
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
	pool   *connPool
	closed chan struct{}
	errCh  chan error
	laddr  net.Addr

	limiter *rateLimiter

	mu sync.Mutex
}

type rateLimiter struct {
	mu        sync.Mutex
	counts    map[string]int
	limit     int
	stop      chan struct{}
	closeOnce sync.Once
}

func newRateLimiter(limit int) *rateLimiter {
	rl := &rateLimiter{
		counts: make(map[string]int),
		limit:  limit,
		stop:   make(chan struct{}),
	}
	go rl.run()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
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
			rl.counts = make(map[string]int)
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
	l.pool = newConnPool(l.md.ttl, l.logger)
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

		// Access Control
		if !l.checkPacket(raddr) {
			pool.Put(buf)
			continue
		}

		// Rate limit check
		if l.limiter != nil {
			host, _, _ := net.SplitHostPort(raddr.String())
			if !l.limiter.allow(host) {
				pool.Put(buf)
				continue
			}
		}

		c := l.getConn(raddr)
		if c == nil {
			pool.Put(buf)
			continue
		}

		if err := c.WriteQueue(buf[:n]); err != nil {
			pool.Put(buf)
			if l.logger != nil {
				l.logger.Warn("UDP listener discarded packet from %s: %v", raddr.String(), err)
			}
		}
	}
}

func (l *Listener) getConn(raddr net.Addr) *udpConn {
	if raddr == nil {
		return nil
	}
	if c, ok := l.pool.Get(raddr.String()); ok && !c.isClosed() {
		return c
	}

	c := newUDPConn(l.conn, l.Addr(), raddr, l.md.readQueueSize, l.md.keepalive)
	select {
	case l.cqueue <- c:
		l.pool.Set(raddr.String(), c)
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
	if v := getInt(md.Get("backlog")); v > 0 {
		l.md.backlog = v
	}
	if v := getInt(md.Get("read_queue")); v > 0 {
		l.md.readQueueSize = v
	}
	if v := getInt(md.Get("read_buffer")); v > 0 {
		l.md.readBufferSize = v
	}
	if v := getDuration(md.Get("udp_idle")); v > 0 {
		l.md.ttl = v
	}
	if v := getDuration(md.Get("ttl")); v > 0 {
		l.md.ttl = v
	}
	if v := md.Get("keepalive"); v != nil {
		l.md.keepalive = getBool(v)
	}
	if v := getInt(md.Get("rate_limit")); v > 0 {
		l.md.rateLimit = v
	}
	if v := getString(md.Get("allow_cidr")); v != "" {
		for _, s := range strings.Split(v, ",") {
			if _, ipnet, err := net.ParseCIDR(strings.TrimSpace(s)); err == nil {
				l.md.allowCIDR = append(l.md.allowCIDR, ipnet)
			}
		}
	}
	if v := md.Get("udp_block_private"); v != nil {
		l.md.blockPrivate = getBool(v)
	} else {
		l.md.blockPrivate = true // Default to true
	}
}

func (l *Listener) checkPacket(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
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

func getString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return ""
	}
}

type connPool struct {
	m      sync.Map
	ttl    time.Duration
	closed chan struct{}
	logger *logging.Logger
}

func newConnPool(ttl time.Duration, logger *logging.Logger) *connPool {
	if ttl <= 0 {
		ttl = config.DefaultUDPIdleTimeout
	}
	p := &connPool{
		ttl:    ttl,
		closed: make(chan struct{}),
		logger: logger,
	}
	go p.idleCheck()
	return p
}

func (p *connPool) Get(key string) (*udpConn, bool) {
	if v, ok := p.m.Load(key); ok {
		c, ok := v.(*udpConn)
		return c, ok
	}
	return nil, false
}

func (p *connPool) Set(key string, c *udpConn) {
	p.m.Store(key, c)
}

func (p *connPool) Delete(key string) {
	p.m.Delete(key)
}

func (p *connPool) Close() {
	select {
	case <-p.closed:
		return
	default:
		close(p.closed)
	}
	p.m.Range(func(_, value any) bool {
		if c, ok := value.(*udpConn); ok && c != nil {
			_ = c.Close()
		}
		return true
	})
}

func (p *connPool) idleCheck() {
	ticker := time.NewTicker(p.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			size := 0
			idles := 0
			p.m.Range(func(key, value any) bool {
				c, ok := value.(*udpConn)
				if !ok || c == nil {
					p.Delete(key.(string))
					return true
				}
				size++
				if c.IsIdle() {
					idles++
					p.Delete(key.(string))
					_ = c.Close()
					return true
				}
				c.SetIdle(true)
				return true
			})
			if idles > 0 && p.logger != nil {
				p.logger.Debug("UDP listener idle cleanup: size=%d idle=%d", size, idles)
			}
		case <-p.closed:
			return
		}
	}
}

type udpConn struct {
	net.PacketConn
	localAddr  net.Addr
	remoteAddr net.Addr
	rc         chan []byte
	idle       int32
	closed     chan struct{}
	closeMu    sync.Mutex
	keepalive  bool
}

func newUDPConn(c net.PacketConn, laddr, raddr net.Addr, queueSize int, keepalive bool) *udpConn {
	if queueSize <= 0 {
		queueSize = defaultReadQueueSize
	}
	return &udpConn{
		PacketConn: c,
		localAddr:  laddr,
		remoteAddr: raddr,
		rc:         make(chan []byte, queueSize),
		closed:     make(chan struct{}),
		keepalive:  keepalive,
	}
}

func (c *udpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case buf := <-c.rc:
		n := copy(b, buf)
		c.SetIdle(false)
		pool.Put(buf)
		return n, c.remoteAddr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *udpConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *udpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if !c.keepalive {
		defer c.Close()
	}
	c.SetIdle(false)
	return c.PacketConn.WriteTo(b, addr)
}

func (c *udpConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.remoteAddr)
}

func (c *udpConn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	select {
	case <-c.closed:
		return nil
	default:
		close(c.closed)
	}
	return nil
}

func (c *udpConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *udpConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *udpConn) IsIdle() bool {
	return atomic.LoadInt32(&c.idle) > 0
}

func (c *udpConn) SetIdle(idle bool) {
	var v int32
	if idle {
		v = 1
	}
	atomic.StoreInt32(&c.idle, v)
}

func (c *udpConn) WriteQueue(b []byte) error {
	c.SetIdle(false)
	select {
	case c.rc <- b:
		return nil
	case <-c.closed:
		return net.ErrClosed
	default:
		return errors.New("recv queue is full")
	}
}

func getInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(t), "%d", &n)
		return n
	default:
		return 0
	}
}

func getBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		t = strings.TrimSpace(strings.ToLower(t))
		return t == "1" || t == "true" || t == "yes" || t == "on"
	default:
		return false
	}
}

func getDuration(v any) time.Duration {
	switch t := v.(type) {
	case time.Duration:
		return t
	case int:
		return time.Duration(t) * time.Second
	case int64:
		return time.Duration(t) * time.Second
	case float64:
		return time.Duration(t) * time.Second
	case string:
		if d, err := time.ParseDuration(strings.TrimSpace(t)); err == nil {
			return d
		}
		var n int64
		if _, err := fmt.Sscanf(strings.TrimSpace(t), "%d", &n); err == nil {
			return time.Duration(n) * time.Second
		}
		return 0
	default:
		return 0
	}
}
