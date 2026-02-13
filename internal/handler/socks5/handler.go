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

	"forward/base/auth"
	inet "forward/base/io/net"
	"forward/base/logging"
	"forward/base/pool"
	socks5util "forward/base/utils/socks5"
	"forward/internal/chain"
	"forward/internal/config"
	corehandler "forward/internal/handler"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/router"
)

const (
	version5 = 0x05

	methodNoAuth   = 0x00
	methodUserPass = 0x02

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03
)

func init() {
	registry.HandlerRegistry().Register("socks5", NewHandler)
}

type Handler struct {
	options corehandler.Options
	auth    auth.Authenticator

	requireAuth     bool
	handshakeTimout time.Duration
	udpIdle         time.Duration
	maxUDPSessions  int
}

func NewHandler(opts ...corehandler.Option) corehandler.Handler {
	options := corehandler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	user := ""
	pass := ""
	if options.Auth != nil {
		user = options.Auth.Username()
		pass, _ = options.Auth.Password()
	}
	requireAuth := user != "" || pass != ""

	h := &Handler{
		options:         options,
		auth:            auth.FromUserPass(user, pass),
		requireAuth:     requireAuth,
		handshakeTimout: config.DefaultHandshakeTimeout,
		udpIdle:         config.DefaultUDPIdleTimeout,
		maxUDPSessions:  config.DefaultMaxUDPSessions,
	}
	if h.options.Router == nil {
		h.options.Router = router.NewStatic(chain.NewRoute())
	}
	return h
}

func (h *Handler) Init(md metadata.Metadata) error {
	if md == nil {
		return nil
	}
	if v := md.Get("handshake_timeout"); v != nil {
		if t, ok := v.(time.Duration); ok && t > 0 {
			h.handshakeTimout = t
		}
	}
	if v := md.Get("udp_idle"); v != nil {
		if t, ok := v.(time.Duration); ok && t > 0 {
			h.udpIdle = t
		}
	}
	if v := md.Get("max_udp_sessions"); v != nil {
		if n, ok := v.(int); ok && n > 0 {
			h.maxUDPSessions = n
		}
	}
	return nil
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn, _ ...corehandler.HandleOption) error {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	local := conn.LocalAddr().String()
	h.options.Logger.Debug("SOCKS5 connection %s -> %s", remote, local)

	_ = conn.SetReadDeadline(time.Now().Add(h.handshakeTimout))

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	if err := h.negotiateAuth(br, bw); err != nil {
		if ctx.Err() == nil {
			h.options.Logger.Error("SOCKS5 negotiate error: %v", err)
		}
		return err
	}

	cmd, dest, err := h.readRequest(br, bw)
	if err != nil {
		if ctx.Err() == nil {
			h.options.Logger.Error("SOCKS5 request error: %v", err)
		}
		return err
	}

	switch cmd {
	case cmdConnect:
		return h.handleConnect(ctx, conn, bw, dest)
	case cmdUDPAssociate:
		return h.handleUDP(ctx, conn, bw)
	default:
		_ = h.writeReply(bw, 0x07, "")
		return nil
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
	h.options.Logger.Debug("SOCKS5 auth method selected=%d", required)
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
	h.options.Logger.Debug("SOCKS5 request cmd=%d dst=%s", cmd, dest)
	return cmd, dest, nil
}

func (h *Handler) handleConnect(ctx context.Context, conn net.Conn, bw *bufio.Writer, dest string) error {
	_ = conn.SetReadDeadline(time.Time{})

	route, err := h.options.Router.Route(ctx, "tcp", dest)
	if err != nil {
		h.options.Logger.Error("SOCKS5 route error: %v", err)
		_ = h.writeReply(bw, 0x05, "")
		return err
	}
	if route == nil {
		route = chain.NewRoute()
	}

	up, err := route.Dial(ctx, "tcp", dest)
	if err != nil {
		h.options.Logger.Error("SOCKS5 connect dial error: %v", err)
		_ = h.writeReply(bw, 0x05, "")
		return err
	}
	defer up.Close()

	bind := hostPortFromAddr(up.LocalAddr())
	_ = h.writeReply(bw, 0x00, bind)

	bytes, dur, err := inet.Bidirectional(ctx, conn, up)
	h.options.Logger.Debug("SOCKS5 CONNECT closed %s -> %s bytes=%d dur=%s", conn.RemoteAddr().String(), dest, bytes, dur)
	return err
}

func (h *Handler) handleUDP(ctx context.Context, conn net.Conn, bw *bufio.Writer) error {
	_ = conn.SetReadDeadline(time.Time{})

	laddr := conn.LocalAddr()
	var ip net.IP
	switch ta := laddr.(type) {
	case *net.TCPAddr:
		ip = ta.IP
	case *net.UDPAddr:
		ip = ta.IP
	}
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		h.options.Logger.Error("SOCKS5 udp listen error: %v", err)
		_ = h.writeReply(bw, 0x01, "")
		return err
	}
	defer udpLn.Close()

	// 智能选择返回给客户端的绑定地址，避免泄露内网 IP
	bind := h.getSafeBindAddr(conn, udpLn)
	if err := h.writeReply(bw, 0x00, bind); err != nil {
		return err
	}

	h.options.Logger.Debug("SOCKS5 UDP relay at %s for %s", bind, conn.RemoteAddr().String())

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer cancel()
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	}()

	var expectedIP net.IP
	switch addr := conn.RemoteAddr().(type) {
	case *net.TCPAddr:
		expectedIP = addr.IP
	case *net.UDPAddr:
		expectedIP = addr.IP
	}

	sess := newUDPSession(h.options.Router, h.log(), udpLn, h.udpIdle, expectedIP, h.maxUDPSessions)
	sess.run(ctx)
	return nil
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
	router  router.Router
	logger  *logging.Logger
	relay   *net.UDPConn
	idle    time.Duration
	maxSess int

	expectedIP net.IP
	mu         sync.Mutex
	sessions   map[string]*udpPeer
	sf         singleflight.Group
}

type udpPeer struct {
	conn     net.Conn
	dest     string
	lastSeen atomic.Int64
}

func newUDPSession(r router.Router, log *logging.Logger, relay *net.UDPConn, idle time.Duration, expectedIP net.IP, maxSessions int) *udpSession {
	return &udpSession{
		router:     r,
		logger:     log,
		relay:      relay,
		idle:       idle,
		expectedIP: expectedIP,
		maxSess:    maxSessions,
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
			s.logf(logging.LevelError, "SOCKS5 UDP read error: %v", err)
			continue
		}
		if n == 0 {
			continue
		}

		if len(s.expectedIP) > 0 && !src.IP.Equal(s.expectedIP) {
			continue
		}

		dest, payload, err := parseUDPRequest(buf[:n])
		if err != nil {
			s.logf(logging.LevelDebug, "SOCKS5 UDP parse error: %v", err)
			continue
		}

		peer := s.getOrCreatePeer(ctx, dest, src)
		if peer == nil {
			continue
		}
		peer.lastSeen.Store(time.Now().UnixNano())

		if _, err := peer.conn.Write(payload); err != nil {
			s.logf(logging.LevelError, "SOCKS5 UDP write upstream error: %v", err)
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
	if len(s.sessions) >= s.maxSess {
		s.mu.Unlock()
		s.logf(logging.LevelWarn, "SOCKS5 UDP session limit reached")
		return nil
	}
	s.mu.Unlock()

	result, _, _ := s.sf.Do(key, func() (interface{}, error) {
		s.mu.Lock()
		if p := s.sessions[key]; p != nil {
			s.mu.Unlock()
			return p, nil
		}
		if len(s.sessions) >= s.maxSess {
			s.mu.Unlock()
			return nil, nil
		}
		s.mu.Unlock()

		route, err := s.router.Route(ctx, "udp", dest)
		if err != nil {
			s.logf(logging.LevelError, "SOCKS5 UDP route error: %v", err)
			return nil, err
		}
		if route == nil {
			route = chain.NewRoute()
		}

		c, err := route.Dial(ctx, "udp", dest)
		if err != nil {
			s.logf(logging.LevelError, "SOCKS5 UDP dial %s error: %v", dest, err)
			return nil, err
		}

		s.logf(logging.LevelDebug, "SOCKS5 UDP %s -> %s", src.String(), dest)

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

func (s *udpSession) logf(level logging.Level, format string, args ...any) {
	if s.logger == nil {
		return
	}
	switch level {
	case logging.LevelDebug:
		s.logger.Debug(format, args...)
	case logging.LevelInfo:
		s.logger.Info(format, args...)
	case logging.LevelWarn:
		s.logger.Warn(format, args...)
	case logging.LevelError:
		s.logger.Error(format, args...)
	}
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

// getSafeBindAddr 返回安全的绑定地址，避免泄露内网 IP
// 当 UDP 监听在 0.0.0.0 时，使用客户端 TCP 连接的本地 IP
func (h *Handler) getSafeBindAddr(clientConn net.Conn, udpLn *net.UDPConn) string {
	udpAddr := udpLn.LocalAddr().(*net.UDPAddr)
	// 如果监听在未指定地址，使用客户端连接的本地地址
	if udpAddr.IP.IsUnspecified() {
		if tcpAddr, ok := clientConn.LocalAddr().(*net.TCPAddr); ok {
			return net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(udpAddr.Port))
		}
	}
	return hostPortFromAddr(udpLn.LocalAddr())
}

func (h *Handler) logf(level logging.Level, format string, args ...any) {
	if h.options.Logger == nil {
		return
	}
	switch level {
	case logging.LevelDebug:
		h.options.Logger.Debug(format, args...)
	case logging.LevelInfo:
		h.options.Logger.Info(format, args...)
	case logging.LevelWarn:
		h.options.Logger.Warn(format, args...)
	case logging.LevelError:
		h.options.Logger.Error(format, args...)
	}
}

func (h *Handler) log() *logging.Logger {
	return h.options.Logger
}
