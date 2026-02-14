package hysteria2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	hyserver "github.com/apernet/hysteria/core/v2/server"
	hyauth "github.com/apernet/hysteria/extras/v2/auth"
	hyobfs "github.com/apernet/hysteria/extras/v2/obfs"

	"forward/base/logging"
	"forward/internal/chain"
	"forward/internal/config"
	ctls "forward/internal/config/tls"
	"forward/internal/router"
)

func Serve(ctx context.Context, cfg config.Config, rt router.Router) error {
	if rt == nil {
		rt = router.NewStatic(chain.NewRouteWithTimeout(cfg.DialTimeout))
	}

	pc, err := net.ListenPacket("udp", cfg.Listen.Address())
	if err != nil {
		return fmt.Errorf("hysteria2 listen udp: %w", err)
	}

	pc, err = wrapObfuscation(pc, cfg.Listen.Query)
	if err != nil {
		_ = pc.Close()
		return err
	}

	tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{})
	if err != nil {
		_ = pc.Close()
		return err
	}

	authValue, err := decodeAuthFromUser(cfg.Listen.User)
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("hysteria2 decode auth: %w", err)
	}

	authenticator := hyserver.Authenticator(&allowAllAuthenticator{})
	if authValue != "" {
		authenticator = &hyauth.PasswordAuthenticator{Password: authValue}
	}

	hyCfg := &hyserver.Config{
		TLSConfig: hyserver.TLSConfig{
			Certificates:   tlsCfg.Certificates,
			GetCertificate: tlsCfg.GetCertificate,
			ClientCAs:      tlsCfg.ClientCAs,
		},
		Conn:          pc,
		Authenticator: authenticator,
		Outbound: &routeOutbound{
			router:      rt,
			dialTimeout: cfg.DialTimeout,
			logger:      cfg.Logger,
		},
		UDPIdleTimeout: cfg.UDPIdleTimeout,
		EventLogger: &serverEventLogger{
			logger: cfg.Logger,
		},
	}

	s, err := hyserver.NewServer(hyCfg)
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("hysteria2 new server: %w", err)
	}

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	if cfg.Logger != nil {
		cfg.Logger.Info("Forward internal hysteria2 proxy listening on %s", cfg.Listen.Address())
	}

	err = s.Serve()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func wrapObfuscation(conn net.PacketConn, q url.Values) (net.PacketConn, error) {
	obfsType := strings.ToLower(strings.TrimSpace(q.Get("obfs")))
	switch obfsType {
	case "", "plain":
		return conn, nil
	case "salamander":
		password := q.Get("obfs-password")
		ob, err := hyobfs.NewSalamanderObfuscator([]byte(password))
		if err != nil {
			return nil, fmt.Errorf("hysteria2 obfs-password: %w", err)
		}
		return hyobfs.WrapPacketConn(conn, ob), nil
	default:
		return nil, fmt.Errorf("hysteria2 unsupported obfs type: %s", obfsType)
	}
}

func decodeAuthFromUser(u *url.Userinfo) (string, error) {
	if u == nil {
		return "", nil
	}
	v, err := url.QueryUnescape(u.String())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(v), nil
}

type allowAllAuthenticator struct{}

func (a *allowAllAuthenticator) Authenticate(_ net.Addr, _ string, _ uint64) (bool, string) {
	return true, "anonymous"
}

type routeOutbound struct {
	router      router.Router
	dialTimeout time.Duration
	logger      *logging.Logger
}

func (o *routeOutbound) TCP(reqAddr string) (net.Conn, error) {
	return o.routeDial("tcp", reqAddr)
}

func (o *routeOutbound) UDP(reqAddr string) (hyserver.UDPConn, error) {
	return newRouteUDPConn(o, reqAddr)
}

func (o *routeOutbound) routeDial(network, address string) (net.Conn, error) {
	ctx := context.Background()
	if o.dialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.dialTimeout)
		defer cancel()
	}

	rt, err := o.router.Route(ctx, network, address)
	if err != nil {
		o.logger.Error("Hysteria2 %s route error for %s: %v", strings.ToUpper(network), address, err)
		return nil, err
	}
	if rt == nil {
		rt = chain.NewRouteWithTimeout(o.dialTimeout)
	}
	o.logger.Debug("Hysteria2 %s route via %s -> %s", strings.ToUpper(network), chain.RouteSummary(rt), address)
	conn, err := rt.Dial(ctx, network, address)
	if err != nil {
		o.logger.Error("Hysteria2 %s dial error for %s: %v", strings.ToUpper(network), address, err)
		return nil, err
	}
	return conn, nil
}

type routeUDPConn struct {
	outbound *routeOutbound

	mu          sync.Mutex
	conn        net.Conn
	currentAddr string
	generation  uint64
	closed      bool

	recvCh  chan udpReadResult
	errCh   chan error
	closeCh chan struct{}
	once    sync.Once
}

type udpReadResult struct {
	data []byte
	addr string
}

func newRouteUDPConn(outbound *routeOutbound, reqAddr string) (*routeUDPConn, error) {
	c := &routeUDPConn{
		outbound: outbound,
		recvCh:   make(chan udpReadResult, 64),
		errCh:    make(chan error, 1),
		closeCh:  make(chan struct{}),
	}
	if err := c.switchConnLocked(reqAddr); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *routeUDPConn) ReadFrom(b []byte) (int, string, error) {
	select {
	case pkt := <-c.recvCh:
		n := copy(b, pkt.data)
		return n, pkt.addr, nil
	case err := <-c.errCh:
		return 0, "", err
	case <-c.closeCh:
		return 0, "", net.ErrClosed
	}
}

func (c *routeUDPConn) WriteTo(b []byte, addr string) (int, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 0, fmt.Errorf("hysteria2 udp empty destination")
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if !sameUDPAddr(c.currentAddr, addr) {
		if err := c.switchConnLocked(addr); err != nil {
			c.mu.Unlock()
			return 0, err
		}
	}
	conn := c.conn
	c.mu.Unlock()

	return conn.Write(b)
}

func (c *routeUDPConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closeCh)
		c.mu.Lock()
		c.closed = true
		if c.conn != nil {
			err = c.conn.Close()
		}
		c.mu.Unlock()
	})
	return err
}

func (c *routeUDPConn) switchConnLocked(addr string) error {
	newConn, err := c.outbound.routeDial("udp", addr)
	if err != nil {
		return err
	}

	oldConn := c.conn
	c.generation++
	gen := c.generation
	c.conn = newConn
	c.currentAddr = addr

	go c.readLoop(newConn, addr, gen)
	if oldConn != nil {
		_ = oldConn.Close()
	}
	return nil
}

func (c *routeUDPConn) readLoop(conn net.Conn, addr string, generation uint64) {
	buf := make([]byte, 64*1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if c.isCurrentGeneration(generation) {
				select {
				case c.errCh <- err:
				default:
				}
			}
			return
		}

		if !c.isCurrentGeneration(generation) {
			return
		}

		data := append([]byte(nil), buf[:n]...)
		select {
		case c.recvCh <- udpReadResult{data: data, addr: addr}:
		case <-c.closeCh:
			return
		}
	}
}

func (c *routeUDPConn) isCurrentGeneration(generation uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed && c.generation == generation
}

func sameUDPAddr(a, b string) bool {
	return normalizeUDPAddr(a) == normalizeUDPAddr(b)
}

func normalizeUDPAddr(addr string) string {
	h, p, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return strings.ToLower(strings.TrimSpace(addr))
	}
	h = strings.Trim(strings.ToLower(h), "[]")
	return net.JoinHostPort(h, p)
}



type serverEventLogger struct {
	logger *logging.Logger
}

func (l *serverEventLogger) Connect(addr net.Addr, id string, tx uint64) {
	l.logger.Info("Hysteria2 connection %s id=%s tx=%d", addrString(addr), id, tx)
}

func (l *serverEventLogger) Disconnect(addr net.Addr, id string, err error) {
	if err == nil || errors.Is(err, net.ErrClosed) {
		l.logger.Info("Hysteria2 connection closed %s id=%s", addrString(addr), id)
		return
	}
	l.logger.Warn("Hysteria2 connection closed with error %s id=%s err=%v", addrString(addr), id, err)
}

func (l *serverEventLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	l.logger.Info("Hysteria2 TCP %s id=%s -> %s", addrString(addr), id, reqAddr)
}

func (l *serverEventLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	if err == nil || errors.Is(err, net.ErrClosed) {
		l.logger.Info("Hysteria2 TCP closed %s id=%s -> %s", addrString(addr), id, reqAddr)
		return
	}
	l.logger.Warn("Hysteria2 TCP error %s id=%s -> %s err=%v", addrString(addr), id, reqAddr, err)
}

func (l *serverEventLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	l.logger.Info("Hysteria2 UDP %s id=%s sid=%d -> %s", addrString(addr), id, sessionID, reqAddr)
}

func (l *serverEventLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	if err == nil || errors.Is(err, net.ErrClosed) {
		l.logger.Info("Hysteria2 UDP closed %s id=%s sid=%d", addrString(addr), id, sessionID)
		return
	}
	l.logger.Warn("Hysteria2 UDP error %s id=%s sid=%d err=%v", addrString(addr), id, sessionID, err)
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
