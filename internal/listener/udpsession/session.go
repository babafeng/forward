package udpsession

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"forward/base/logging"
	"forward/base/pool"
	"forward/internal/config"
)

type Session interface {
	IsIdle() bool
	SetIdle(bool)
	Close() error
}

type Pool[K comparable, V Session] struct {
	m      sync.Map
	ttl    time.Duration
	closed chan struct{}
	logger *logging.Logger
	label  string
}

func NewPool[K comparable, V Session](ttl time.Duration, logger *logging.Logger, label string) *Pool[K, V] {
	if ttl <= 0 {
		ttl = config.DefaultUDPIdleTimeout
	}
	p := &Pool[K, V]{
		ttl:    ttl,
		closed: make(chan struct{}),
		logger: logger,
		label:  label,
	}
	go p.idleCheck()
	return p
}

func (p *Pool[K, V]) Get(key K) (V, bool) {
	if v, ok := p.m.Load(key); ok {
		c, ok := v.(V)
		return c, ok
	}
	var zero V
	return zero, false
}

func (p *Pool[K, V]) Set(key K, c V) {
	p.m.Store(key, c)
}

func (p *Pool[K, V]) Delete(key K) {
	p.m.Delete(key)
}

func (p *Pool[K, V]) Close() {
	select {
	case <-p.closed:
		return
	default:
		close(p.closed)
	}
	p.m.Range(func(_, value any) bool {
		if c, ok := value.(V); ok {
			_ = c.Close()
		}
		return true
	})
}

func (p *Pool[K, V]) idleCheck() {
	ticker := time.NewTicker(p.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			size := 0
			idles := 0
			p.m.Range(func(key, value any) bool {
				c, ok := value.(V)
				if !ok {
					p.m.Delete(key)
					return true
				}
				size++
				if c.IsIdle() {
					idles++
					p.m.Delete(key)
					_ = c.Close()
					return true
				}
				c.SetIdle(true)
				return true
			})
			if idles > 0 && p.logger != nil {
				p.logger.Debug("%s idle cleanup: size=%d idle=%d", p.label, size, idles)
			}
		case <-p.closed:
			return
		}
	}
}

type Conn struct {
	net.PacketConn
	localAddr  net.Addr
	remoteAddr net.Addr
	rc         chan []byte
	idle       int32
	closed     chan struct{}
	closeMu    sync.Mutex
	keepalive  bool
}

func NewConn(c net.PacketConn, laddr, raddr net.Addr, queueSize int, keepalive bool) *Conn {
	if queueSize <= 0 {
		queueSize = 128
	}
	return &Conn{
		PacketConn: c,
		localAddr:  laddr,
		remoteAddr: raddr,
		rc:         make(chan []byte, queueSize),
		closed:     make(chan struct{}),
		keepalive:  keepalive,
	}
}

func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
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

func (c *Conn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *Conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if !c.keepalive {
		defer c.Close()
	}
	c.SetIdle(false)
	return c.PacketConn.WriteTo(b, addr)
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.remoteAddr)
}

func (c *Conn) Close() error {
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

func (c *Conn) IsClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *Conn) IsIdle() bool {
	return atomic.LoadInt32(&c.idle) > 0
}

func (c *Conn) SetIdle(idle bool) {
	var v int32
	if idle {
		v = 1
	}
	atomic.StoreInt32(&c.idle, v)
}

func (c *Conn) WriteQueue(b []byte) error {
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
