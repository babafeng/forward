package socks5

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"forward/internal/auth"
	"forward/internal/config"
	"forward/internal/dialer"
	netio "forward/internal/io/net"
	"forward/internal/logging"
	"forward/internal/pool"
	"forward/internal/route"
	socks5util "forward/internal/utils/socks5"
)

const (
	version5 = 0x05

	methodNoAuth   = 0x00
	methodUserPass = 0x02

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03
)

type Handler struct {
	dialer      dialer.Dialer
	log         *logging.Logger
	auth        auth.Authenticator
	requireAuth bool

	udpIdle    time.Duration
	routeStore *route.Store
}

func New(cfg config.Config, d dialer.Dialer) *Handler {
	user, pass, ok := cfg.Listen.UserPass()
	idle := cfg.UDPIdleTimeout
	if idle <= 0 {
		idle = 2 * time.Minute
	}
	return &Handler{
		dialer:      d,
		log:         cfg.Logger,
		auth:        auth.FromUserPass(user, pass),
		requireAuth: ok,
		udpIdle:     idle,
		routeStore:  cfg.RouteStore,
	}
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	h.log.Debug("Forward SOCKS5 Received connection from %s", conn.RemoteAddr())

	_ = conn.SetReadDeadline(time.Now().Add(config.DefaultHandshakeTimeout))

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	if err := h.negotiateAuth(br, bw); err != nil {
		if ctx.Err() == nil {
			h.log.Error("Forward SOCKS5 error: negotiate: %v", err)
		}
		return
	}

	cmd, dest, err := h.readRequest(br, bw)
	if err != nil {
		if ctx.Err() == nil {
			h.log.Error("Forward SOCKS5 error: request: %v", err)
		}
		return
	}

	switch cmd {
	case cmdConnect:
		h.handleConnect(ctx, conn, bw, dest)
	case cmdUDPAssociate:
		h.handleUDP(ctx, conn, bw)
	default:
		_ = h.writeReply(bw, 0x07, "") // command not supported
	}
}

func (h *Handler) negotiateAuth(br *bufio.Reader, bw *bufio.Writer) error {
	ver, err := br.ReadByte()
	if err != nil {
		return err
	}
	if ver != version5 {
		return fmt.Errorf("unsupported version %d", ver)
	}
	nm, err := br.ReadByte()
	if err != nil {
		return err
	}
	methods := make([]byte, int(nm))
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}

	var required byte = methodNoAuth
	if h.requireAuth {
		required = methodUserPass
	}
	if !socks5util.Contains(methods, required) {
		if _, err := bw.Write([]byte{version5, 0xff}); err != nil {
			return fmt.Errorf("write reject: %w", err)
		}
		if err := bw.Flush(); err != nil {
			return fmt.Errorf("flush reject: %w", err)
		}
		return fmt.Errorf("auth method not offered")
	}
	if _, err := bw.Write([]byte{version5, required}); err != nil {
		return fmt.Errorf("write method: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("flush method: %w", err)
	}

	if required == methodUserPass {
		if err := h.handleUserPass(br, bw); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) handleUserPass(br *bufio.Reader, bw *bufio.Writer) error {
	ver, err := br.ReadByte()
	if err != nil {
		return err
	}
	if ver != 0x01 {
		return fmt.Errorf("auth version %d not supported", ver)
	}
	ulen, err := br.ReadByte()
	if err != nil {
		return err
	}
	uname := make([]byte, int(ulen))
	if _, err := io.ReadFull(br, uname); err != nil {
		return err
	}
	plen, err := br.ReadByte()
	if err != nil {
		return err
	}
	pass := make([]byte, int(plen))
	if _, err := io.ReadFull(br, pass); err != nil {
		return err
	}

	if h.auth.Check(string(uname), string(pass)) {
		if _, err := bw.Write([]byte{0x01, 0x00}); err != nil {
			return fmt.Errorf("write auth ok: %w", err)
		}
		if err := bw.Flush(); err != nil {
			return fmt.Errorf("flush auth ok: %w", err)
		}
		return nil
	}
	if _, err := bw.Write([]byte{0x01, 0x01}); err != nil {
		return fmt.Errorf("write auth fail: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("flush auth fail: %w", err)
	}
	return fmt.Errorf("auth failed for user %q", string(uname))
}

func (h *Handler) readRequest(br *bufio.Reader, bw *bufio.Writer) (byte, string, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		return 0, "", err
	}
	if head[0] != version5 {
		return 0, "", fmt.Errorf("unsupported version %d", head[0])
	}
	cmd := head[1]
	atyp := head[3]
	addr, port, err := socks5util.ReadAddr(br, atyp)
	if err != nil {
		_ = h.writeReply(bw, 0x08, "")
		return 0, "", err
	}
	dest := net.JoinHostPort(addr, strconv.Itoa(port))
	h.log.Debug("Forward SOCKS5 request cmd=%d dst=%s", cmd, dest)
	return cmd, dest, nil
}

func (h *Handler) handleConnect(ctx context.Context, conn net.Conn, bw *bufio.Writer, dest string) {
	_ = conn.SetReadDeadline(time.Time{})

	via, err := route.RouteVia(ctx, h.routeStore, h.log, conn.RemoteAddr().String(), dest)
	if err != nil {
		h.log.Error("Forward SOCKS5 route error: %v", err)
		_ = h.writeReply(bw, 0x05, "")
		return
	}
	if route.IsReject(via) {
		_ = h.writeReply(bw, 0x05, "")
		return
	}

	h.log.Info("Forward SOCKS5 Received connection %s --> %s", conn.RemoteAddr(), dest)
	up, err := dialer.DialContextVia(ctx, h.dialer, "tcp", dest, via)
	if err != nil {
		h.log.Error("Forward SOCKS5 connect dial error: %v", err)
		_ = h.writeReply(bw, 0x05, "") // connection refused
		return
	}
	defer up.Close()

	bind := hostPortFromAddr(up.LocalAddr())
	_ = h.writeReply(bw, 0x00, bind)

	h.log.Debug("Forward SOCKS5 CONNECT Connected to upstream %s --> %s", conn.RemoteAddr(), dest)

	bytes, dur, err := netio.Bidirectional(ctx, conn, up)
	if err != nil && ctx.Err() == nil {
		h.log.Error("Forward SOCKS5 connect transfer error: %v", err)
	}
	h.log.Debug("Forward SOCKS5 CONNECT Closed connection %s --> %s transferred %d bytes in %s", conn.RemoteAddr(), dest, bytes, dur)
}

func (h *Handler) handleUDP(ctx context.Context, conn net.Conn, bw *bufio.Writer) {
	_ = conn.SetReadDeadline(time.Time{})

	laddr := conn.LocalAddr()
	var ip net.IP
	if ta, ok := laddr.(*net.TCPAddr); ok && ta != nil {
		ip = ta.IP
	}
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		h.log.Error("Forward SOCKS5 udp listen error: %v", err)
		_ = h.writeReply(bw, 0x01, "")
		return
	}
	defer udpLn.Close()

	bind := hostPortFromAddr(udpLn.LocalAddr())
	if err := h.writeReply(bw, 0x00, bind); err != nil {
		return
	}

	h.log.Debug("Forward SOCKS5 UDP relay at %s", bind)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer cancel()
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	}()

	sess := newUDPSession(h.dialer, h.routeStore, h.log, udpLn, h.udpIdle)
	sess.run(ctx)
}

func (h *Handler) writeReply(bw *bufio.Writer, rep byte, bind string) error {
	addr, portStr := "0.0.0.0", "0"
	if bind != "" {
		host, port, err := net.SplitHostPort(bind)
		if err == nil {
			addr, portStr = host, port
		}
	}
	port, _ := strconv.Atoi(portStr)
	bindAddr, _ := socks5util.EncodeAddr(addr, port)

	reply := []byte{version5, rep, 0x00}
	reply = append(reply, bindAddr...)
	if _, err := bw.Write(reply); err != nil {
		return err
	}
	return bw.Flush()
}

type udpSession struct {
	dialer     dialer.Dialer
	routeStore *route.Store
	log        *logging.Logger

	relay *net.UDPConn

	idle time.Duration

	mu       sync.Mutex
	sessions map[string]*udpPeer
	sf       singleflight.Group
}

type udpPeer struct {
	conn     net.Conn
	dest     string
	lastSeen atomic.Int64
}

func newUDPSession(d dialer.Dialer, routeStore *route.Store, log *logging.Logger, relay *net.UDPConn, idle time.Duration) *udpSession {
	return &udpSession{
		dialer:     d,
		routeStore: routeStore,
		log:        log,
		relay:      relay,
		idle:       idle,
		sessions:   make(map[string]*udpPeer),
	}
}

func (s *udpSession) run(ctx context.Context) {
	buf := pool.Get()
	defer pool.Put(buf)

	for {
		_ = s.relay.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := s.relay.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				s.cleanupIdle()
				continue
			}
			s.log.Error("Forward SOCKS5 UDP read error: %v", err)
			continue
		}
		if n == 0 {
			continue
		}

		dest, payload, err := parseUDPRequest(buf[:n])
		if err != nil {
			s.log.Debug("Forward SOCKS5 UDP parse error: %v", err)
			continue
		}

		peer := s.getOrCreatePeer(ctx, dest, src)
		if peer == nil {
			continue
		}
		peer.lastSeen.Store(time.Now().UnixNano())

		if _, err := peer.conn.Write(payload); err != nil {
			s.log.Error("Forward SOCKS5 UDP write upstream error: %v", err)
			continue
		}
	}
}

func (s *udpSession) getOrCreatePeer(ctx context.Context, dest string, src *net.UDPAddr) *udpPeer {
	key := dest + "|" + src.String()
	s.mu.Lock()
	if p := s.sessions[key]; p != nil {
		s.mu.Unlock()
		return p
	}
	s.mu.Unlock()

	result, _, _ := s.sf.Do(key, func() (interface{}, error) {
		s.mu.Lock()
		if p := s.sessions[key]; p != nil {
			s.mu.Unlock()
			return p, nil
		}
		s.mu.Unlock()

		via, err := route.RouteVia(ctx, s.routeStore, s.log, src.String(), dest)
		if err != nil {
			s.log.Error("Forward SOCKS5 UDP route error: %v", err)
			return nil, err
		}
		if route.IsReject(via) {
			return nil, fmt.Errorf("route rejected")
		}

		c, err := dialer.DialContextVia(ctx, s.dialer, "udp", dest, via)
		if err != nil {
			s.log.Error("Forward SOCKS5 UDP dial %s error: %v", dest, err)
			return nil, err
		}

		s.log.Info("Forward SOCKS5 UDP Received connection %s --> %s", src, dest)

		p := &udpPeer{
			conn: c,
			dest: dest,
		}
		p.lastSeen.Store(time.Now().UnixNano())

		go s.readUpstream(ctx, p, src, key)

		s.mu.Lock()
		s.sessions[key] = p
		s.mu.Unlock()
		return p, nil
	})

	if result == nil {
		return nil
	}
	return result.(*udpPeer)
}

func (s *udpSession) readUpstream(ctx context.Context, p *udpPeer, client *net.UDPAddr, key string) {
	defer func() {
		s.mu.Lock()
		delete(s.sessions, key)
		s.mu.Unlock()
		p.conn.Close()
	}()

	buf := pool.Get()
	defer pool.Put(buf)
	host, portStr, err := net.SplitHostPort(p.dest)
	if err != nil {
		return
	}
	port, _ := strconv.Atoi(portStr)

	for {
		_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := p.conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(time.Unix(0, p.lastSeen.Load())) > s.idle {
					return
				}
				continue
			}
			return
		}

		payload := buf[:n]
		resp, err := buildUDPResponse(host, port, payload)
		if err != nil {
			continue
		}
		_, _ = s.relay.WriteToUDP(resp, client)
		p.lastSeen.Store(time.Now().UnixNano())
	}
}

func (s *udpSession) cleanupIdle() {
	now := time.Now()
	s.mu.Lock()
	for k, p := range s.sessions {
		last := time.Unix(0, p.lastSeen.Load())
		if now.Sub(last) > s.idle {
			_ = p.conn.Close()
			delete(s.sessions, k)
		}
	}
	s.mu.Unlock()
}

func parseUDPRequest(b []byte) (dest string, payload []byte, err error) {
	if len(b) < 4 {
		return "", nil, errors.New("short udp request")
	}
	if b[0] != 0x00 || b[1] != 0x00 {
		return "", nil, errors.New("bad rsv")
	}
	if b[2] != 0x00 {
		return "", nil, errors.New("fragmentation not supported")
	}
	atyp := b[3]
	off := 4
	switch atyp {
	case socks5util.AtypIPv4:
		if len(b) < off+4+2 {
			return "", nil, errors.New("short ipv4 header")
		}
		host := net.IP(b[off : off+4]).String()
		off += 4
		port := int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
		dest = net.JoinHostPort(host, strconv.Itoa(port))
	case socks5util.AtypIPv6:
		if len(b) < off+16+2 {
			return "", nil, errors.New("short ipv6 header")
		}
		host := net.IP(b[off : off+16]).String()
		off += 16
		port := int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
		dest = net.JoinHostPort(host, strconv.Itoa(port))
	case socks5util.AtypDomain:
		if len(b) < off+1 {
			return "", nil, errors.New("short domain header")
		}
		l := int(b[off])
		off++
		if len(b) < off+l+2 {
			return "", nil, errors.New("short domain header")
		}
		host := string(b[off : off+l])
		off += l
		port := int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
		dest = net.JoinHostPort(host, strconv.Itoa(port))
	default:
		return "", nil, fmt.Errorf("unknown atyp %d", atyp)
	}
	return dest, b[off:], nil
}

func buildUDPResponse(host string, port int, payload []byte) ([]byte, error) {
	addr, err := socks5util.EncodeAddr(host, port)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 3+len(addr)+len(payload))
	out = append(out, 0x00, 0x00, 0x00)
	out = append(out, addr...)
	out = append(out, payload...)
	return out, nil
}

func hostPortFromAddr(a net.Addr) string {
	switch v := a.(type) {
	case *net.TCPAddr:
		return net.JoinHostPort(v.IP.String(), strconv.Itoa(v.Port))
	case *net.UDPAddr:
		return net.JoinHostPort(v.IP.String(), strconv.Itoa(v.Port))
	default:
		return a.String()
	}
}
