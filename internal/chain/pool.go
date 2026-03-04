package chain

import (
	"context"
	"net"
	"sync"
	"time"

	"forward/internal/dialer"
)

// DialPool maintains a pool of pre-warmed, handshaked connections to a proxy
// node.  When chainRoute.Dial needs a connection to the first hop, it can
// retrieve one from the pool and skip the TCP + TLS handshake latency
// (~3 RTT).  Only useful for non-multiplexing dialers (TCP/TLS/DTLS);
// multiplexing dialers (H2/H3 PHT) already manage their own connection
// reuse internally.
type DialPool struct {
	dialer dialer.Dialer
	addr   string

	maxIdle int
	ttl     time.Duration

	mu     sync.Mutex
	idle   []poolEntry
	stop   chan struct{}
	closed bool
}

type poolEntry struct {
	conn    net.Conn
	created time.Time
}

// pooledConn is a marker wrapper so Transport.Handshake can recognise that the
// connection was taken from the pool and is already handshaked.
type pooledConn struct {
	net.Conn
}

// NewDialPool creates a connection pool for the given dialer + address pair.
// maxIdle controls how many ready connections are kept warm.
// ttl controls the maximum age of an idle connection before it is discarded.
func NewDialPool(d dialer.Dialer, addr string, maxIdle int, ttl time.Duration) *DialPool {
	if maxIdle <= 0 {
		maxIdle = 2
	}
	if ttl <= 0 {
		ttl = 90 * time.Second
	}
	p := &DialPool{
		dialer:  d,
		addr:    addr,
		maxIdle: maxIdle,
		ttl:     ttl,
		stop:    make(chan struct{}),
	}
	go p.warmBackground()
	return p
}

// Get returns a handshaked connection from the pool, or dials a new one if the
// pool is empty.  The returned connection is wrapped in *pooledConn so
// Transport.Handshake can skip re-handshaking.
func (p *DialPool) Get(ctx context.Context) (net.Conn, error) {
	if conn := p.tryGet(); conn != nil {
		return &pooledConn{Conn: conn}, nil
	}
	// Pool empty – fall through to live dial+handshake; not wrapped in
	// pooledConn so Transport.Handshake will run normally.
	return p.dialer.Dial(ctx, p.addr)
}

func (p *DialPool) tryGet() net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for len(p.idle) > 0 {
		e := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if now.Sub(e.created) > p.ttl {
			e.conn.Close()
			continue
		}
		return e.conn
	}
	return nil
}

// Close shuts down the warm-up goroutine and closes all idle connections.
func (p *DialPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	close(p.stop)
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	for _, e := range idle {
		e.conn.Close()
	}
}

// warmBackground continuously fills the pool up to maxIdle.
func (p *DialPool) warmBackground() {
	// Initial fill with a short delay to let the server start
	select {
	case <-time.After(500 * time.Millisecond):
	case <-p.stop:
		return
	}
	p.fill()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.fill()
		case <-p.stop:
			return
		}
	}
}

func (p *DialPool) fill() {
	p.mu.Lock()
	need := p.maxIdle - len(p.idle)
	stopped := p.closed
	p.mu.Unlock()
	if need <= 0 || stopped {
		return
	}

	for i := 0; i < need; i++ {
		select {
		case <-p.stop:
			return
		default:
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := p.dialer.Dial(ctx, p.addr)
		if err != nil {
			cancel()
			return // server likely not ready; try again next cycle
		}
		// Handshake if the dialer supports it
		if h, ok := p.dialer.(dialer.Handshaker); ok {
			hc, err := h.Handshake(ctx, conn)
			if err != nil {
				conn.Close()
				cancel()
				return
			}
			conn = hc
		}
		cancel()

		p.mu.Lock()
		if p.closed || len(p.idle) >= p.maxIdle {
			p.mu.Unlock()
			conn.Close()
			return
		}
		p.idle = append(p.idle, poolEntry{conn: conn, created: time.Now()})
		p.mu.Unlock()
	}
}

// IsPooled returns true if the connection was retrieved from a DialPool and
// is already handshaked.
func IsPooled(conn net.Conn) bool {
	_, ok := conn.(*pooledConn)
	return ok
}

// UnwrapPooled strips the pooledConn wrapper, returning the underlying
// handshaked connection.
func UnwrapPooled(conn net.Conn) net.Conn {
	if pc, ok := conn.(*pooledConn); ok {
		return pc.Conn
	}
	return conn
}
