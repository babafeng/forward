package tproxy

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
	pool   *connPool
	closed chan struct{}
	errCh  chan error
	laddr  net.Addr

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
		l.pool = newConnPool(l.md.ttl, l.logger)
	}

	l.cqueue = make(chan net.Conn, l.md.backlog)
	l.closed = make(chan struct{})
	l.errCh = make(chan error, 1)

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
		if l.logger != nil {
			l.logger.Info("Listener accepted %s -> %s", c.RemoteAddr().String(), c.LocalAddr().String())
		}
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
	key := fmt.Sprintf("%s->%s", raddr.String(), dstAddr.String())
	if c, ok := l.pool.Get(key); ok && !c.isClosed() {
		return c
	}

	uc := newUDPConn(l.udpLn, dstAddr, raddr, l.md.readQueueSize, l.md.keepalive)
	md := metadata.New(map[string]any{
		metadata.KeyOriginalDst: dstAddr.String(),
		metadata.KeyNetwork:     "udp",
	})
	tc := &udpMetaConn{udpConn: uc, md: md}

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
	if v := getString(md.Get("network")); v != "" {
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

type tcpMetaConn struct {
	net.Conn
	md metadata.Metadata
}

func (c *tcpMetaConn) Metadata() metadata.Metadata {
	return c.md
}

type udpMetaConn struct {
	*udpConn
	md metadata.Metadata
}

func (c *udpMetaConn) Metadata() metadata.Metadata {
	return c.md
}

func (c *udpMetaConn) isClosed() bool {
	if c == nil || c.udpConn == nil {
		return true
	}
	return c.udpConn.isClosed()
}

func (c *udpMetaConn) WriteQueue(b []byte) error {
	if c == nil || c.udpConn == nil {
		return errors.New("tproxy: udp conn required")
	}
	return c.udpConn.WriteQueue(b)
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

func (p *connPool) Get(key string) (*udpMetaConn, bool) {
	if v, ok := p.m.Load(key); ok {
		c, ok := v.(*udpMetaConn)
		return c, ok
	}
	return nil, false
}

func (p *connPool) Set(key string, c *udpMetaConn) {
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
		if c, ok := value.(*udpMetaConn); ok && c != nil {
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
				c, ok := value.(*udpMetaConn)
				if !ok || c == nil {
					p.Delete(key.(string))
					return true
				}
				size++
				if uc := c.udpConn; uc != nil && uc.IsIdle() {
					idles++
					p.Delete(key.(string))
					_ = c.Close()
					return true
				}
				return true
			})
			if idles > 0 && p.logger != nil {
				p.logger.Debug("TPROXY UDP idle cleanup: size=%d idle=%d", size, idles)
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

func getString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return ""
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

var errMissingAddr = errors.New("missing listen address")
