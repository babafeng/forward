package phtserver

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"forward/base/logging"
	"forward/base/pool"
	"forward/base/transport/pht"
)

const (
	DefaultBacklog           = 128
	DefaultReadBufferSize    = 32 * 1024
	DefaultReadTimeout       = 10 * time.Second
	DefaultReadHeaderTimeout = 30 * time.Second
	maxPushBytes             = 1 << 20
)

var (
	CleanupTickInterval = 30 * time.Second
	SessionIdleTimeout  = 60 * time.Second
)

type serverOptions struct {
	authorizePath     string
	pushPath          string
	pullPath          string
	backlog           int
	tlsEnabled        bool
	tlsConfig         *tls.Config
	readBufferSize    int
	readTimeout       time.Duration
	readHeaderTimeout time.Duration
	maxStreams        uint32
	idleTimeout       time.Duration
	readIdleTimeout   time.Duration
	pingTimeout       time.Duration
	secret            string
	logger            *logging.Logger
}

type phtSession struct {
	conn     net.Conn
	lastSeen int64
	sourceIP string
}

type ServerOption func(opts *serverOptions)

func PathServerOption(authorizePath, pushPath, pullPath string) ServerOption {
	return func(opts *serverOptions) {
		opts.authorizePath = authorizePath
		opts.pullPath = pullPath
		opts.pushPath = pushPath
	}
}

func BacklogServerOption(backlog int) ServerOption {
	return func(opts *serverOptions) {
		opts.backlog = backlog
	}
}

func TLSConfigServerOption(tlsConfig *tls.Config) ServerOption {
	return func(opts *serverOptions) {
		opts.tlsConfig = tlsConfig
	}
}

func EnableTLSServerOption(enable bool) ServerOption {
	return func(opts *serverOptions) {
		opts.tlsEnabled = enable
	}
}

func ReadBufferSizeServerOption(n int) ServerOption {
	return func(opts *serverOptions) {
		opts.readBufferSize = n
	}
}

func ReadTimeoutServerOption(timeout time.Duration) ServerOption {
	return func(opts *serverOptions) {
		opts.readTimeout = timeout
	}
}

func ReadHeaderTimeoutServerOption(timeout time.Duration) ServerOption {
	return func(opts *serverOptions) {
		opts.readHeaderTimeout = timeout
	}
}

func MaxStreamsServerOption(n uint32) ServerOption {
	return func(opts *serverOptions) {
		opts.maxStreams = n
	}
}

func IdleTimeoutServerOption(timeout time.Duration) ServerOption {
	return func(opts *serverOptions) {
		opts.idleTimeout = timeout
	}
}

func ReadIdleTimeoutServerOption(timeout time.Duration) ServerOption {
	return func(opts *serverOptions) {
		opts.readIdleTimeout = timeout
	}
}

func PingTimeoutServerOption(timeout time.Duration) ServerOption {
	return func(opts *serverOptions) {
		opts.pingTimeout = timeout
	}
}

func LoggerServerOption(logger *logging.Logger) ServerOption {
	return func(opts *serverOptions) {
		opts.logger = logger
	}
}

func SecretServerOption(secret string) ServerOption {
	return func(opts *serverOptions) {
		opts.secret = secret
	}
}

type Server struct {
	addr        net.Addr
	httpServer  *http.Server
	http3Server *http3.Server
	cqueue      chan net.Conn
	conns       sync.Map
	closed      chan struct{}

	options serverOptions
}

func NewServer(addr string, opts ...ServerOption) *Server {
	options := newOptions(opts...)
	s := &Server{
		httpServer: &http.Server{
			Addr:              addr,
			ReadHeaderTimeout: options.readHeaderTimeout,
		},
		cqueue:  make(chan net.Conn, options.backlog),
		closed:  make(chan struct{}),
		options: options,
	}
	s.attachHandlers(s.httpServer)
	return s
}

func NewHTTP2Server(addr string, opts ...ServerOption) *Server {
	options := newOptions(opts...)
	options.tlsEnabled = true
	s := &Server{
		httpServer: &http.Server{
			Addr:              addr,
			ReadHeaderTimeout: options.readHeaderTimeout,
		},
		cqueue:  make(chan net.Conn, options.backlog),
		closed:  make(chan struct{}),
		options: options,
	}
	s.attachHandlers(s.httpServer)
	return s
}

func NewHTTP3Server(addr string, quicConfig *quic.Config, opts ...ServerOption) *Server {
	options := newOptions(opts...)
	s := &Server{
		http3Server: &http3.Server{
			Addr:       addr,
			TLSConfig:  options.tlsConfig,
			QUICConfig: quicConfig,
		},
		cqueue:  make(chan net.Conn, options.backlog),
		closed:  make(chan struct{}),
		options: options,
	}
	mux := http.NewServeMux()
	mux.HandleFunc(options.authorizePath, s.handleAuthorize)
	mux.HandleFunc(options.pushPath, s.handlePush)
	mux.HandleFunc(options.pullPath, s.handlePull)
	s.http3Server.Handler = mux
	return s
}

func newOptions(opts ...ServerOption) serverOptions {
	options := serverOptions{
		authorizePath:     "/authorize",
		pushPath:          "/push",
		pullPath:          "/pull",
		backlog:           DefaultBacklog,
		readBufferSize:    DefaultReadBufferSize,
		readTimeout:       DefaultReadTimeout,
		readHeaderTimeout: DefaultReadHeaderTimeout,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.backlog <= 0 {
		options.backlog = DefaultBacklog
	}
	if options.readBufferSize <= 0 {
		options.readBufferSize = DefaultReadBufferSize
	}
	if options.readTimeout <= 0 {
		options.readTimeout = DefaultReadTimeout
	}
	if options.readHeaderTimeout <= 0 {
		options.readHeaderTimeout = DefaultReadHeaderTimeout
	}
	return options
}

func (s *Server) attachHandlers(server *http.Server) {
	mux := http.NewServeMux()
	mux.HandleFunc(s.options.authorizePath, s.handleAuthorize)
	mux.HandleFunc(s.options.pushPath, s.handlePush)
	mux.HandleFunc(s.options.pullPath, s.handlePull)
	server.Handler = mux
}

func (s *Server) ListenAndServe() error {
	if s.http3Server != nil {
		network := "udp"
		if IsIPv4(s.http3Server.Addr) {
			network = "udp4"
		}
		addr, err := net.ResolveUDPAddr(network, s.http3Server.Addr)
		if err != nil {
			return err
		}
		s.addr = addr
		go s.cleanupLoop()
		return s.http3Server.ListenAndServe()
	}

	if s.options.tlsEnabled && s.options.tlsConfig == nil {
		return errors.New("missing tls config")
	}

	network := "tcp"
	if IsIPv4(s.httpServer.Addr) {
		network = "tcp4"
	}

	ln, err := net.Listen(network, s.httpServer.Addr)
	if err != nil {
		return err
	}

	s.addr = ln.Addr()
	if s.options.tlsEnabled {
		s.httpServer.TLSConfig = s.options.tlsConfig
		h2srv := &http2.Server{
			MaxConcurrentStreams: s.options.maxStreams,
			IdleTimeout:          s.options.idleTimeout,
			ReadIdleTimeout:      s.options.readIdleTimeout,
			PingTimeout:          s.options.pingTimeout,
		}
		if err := http2.ConfigureServer(s.httpServer, h2srv); err != nil {
			return err
		}
		ln = tls.NewListener(ln, s.options.tlsConfig)
	}

	go s.cleanupLoop()
	return s.httpServer.Serve(ln)
}

func (s *Server) cleanupLoop() {
	interval := CleanupTickInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			now := time.Now().UnixNano()
			timeout := int64(SessionIdleTimeout)
			if timeout <= 0 {
				timeout = int64(60 * time.Second)
			}
			s.conns.Range(func(key, value any) bool {
				sess, ok := value.(*phtSession)
				if !ok {
					s.conns.Delete(key)
					return true
				}
				if now-atomic.LoadInt64(&sess.lastSeen) > timeout {
					s.conns.Delete(key)
					sess.conn.Close()
				}
				return true
			})
		}
	}
}

func (s *Server) Accept() (net.Conn, error) {
	select {
	case conn := <-s.cqueue:
		return conn, nil
	case <-s.closed:
		return nil, net.ErrClosed
	}
}

func (s *Server) Close() error {
	select {
	case <-s.closed:
		return http.ErrServerClosed
	default:
		close(s.closed)

		s.conns.Range(func(key, value any) bool {
			if sess, ok := value.(*phtSession); ok {
				sess.conn.Close()
			}
			s.conns.Delete(key)
			return true
		})

		if s.http3Server != nil {
			return s.http3Server.Close()
		}
		if s.httpServer != nil {
			return s.httpServer.Close()
		}
		return nil
	}
}

func (s *Server) Addr() net.Addr {
	return s.addr
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	raddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if raddr == nil {
		raddr = &net.TCPAddr{}
	}
	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	if !authorizedBySecret(r, s.options.secret) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	cid := newToken()
	c1, c2 := net.Pipe()
	c := pht.NewServerConn(c1, s.addr, raddr)

	select {
	case s.cqueue <- c:
	default:
		c.Close()
		if s.options.logger != nil {
			s.options.logger.Warn("pht: connection queue full, client %s discarded", r.RemoteAddr)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	_, _ = w.Write([]byte(fmt.Sprintf("token=%s", cid)))
	s.conns.Store(cid, &phtSession{conn: c2, lastSeen: time.Now().UnixNano(), sourceIP: sourceIP})
}

func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !authorizedBySecret(r, s.options.secret) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	cid := r.Form.Get("token")
	v, ok := s.conns.Load(cid)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	sess := v.(*phtSession)
	if !s.sameSourceIP(sess, r.RemoteAddr, "push") {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	atomic.StoreInt64(&sess.lastSeen, time.Now().UnixNano())
	conn := sess.conn

	r.Body = http.MaxBytesReader(w, r.Body, maxPushBytes)
	scanner := bufio.NewScanner(r.Body)
	buf := pool.Get()
	defer pool.Put(buf)
	scanner.Buffer(buf, maxPushBytes+1)
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			if s.options.logger != nil {
				s.options.logger.Error("pht: push decode error: %v", err)
			}
			s.conns.Delete(cid)
			conn.Close()
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(b) == 0 {
			continue
		}
		if _, err := conn.Write(b); err != nil {
			if s.options.logger != nil {
				s.options.logger.Error("pht: push write error: %v", err)
			}
			s.conns.Delete(cid)
			conn.Close()
			w.WriteHeader(http.StatusGone)
			return
		}
	}

	if err := scanner.Err(); err != nil {
		if s.options.logger != nil {
			s.options.logger.Error("pht: push read error: %v", err)
		}
		s.conns.Delete(cid)
		conn.Close()
		if errors.Is(err, bufio.ErrTooLong) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !authorizedBySecret(r, s.options.secret) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	cid := r.Form.Get("token")
	v, ok := s.conns.Load(cid)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	sess := v.(*phtSession)
	if !s.sameSourceIP(sess, r.RemoteAddr, "pull") {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	atomic.StoreInt64(&sess.lastSeen, time.Now().UnixNano())
	conn := sess.conn

	w.WriteHeader(http.StatusOK)
	if fw, ok := w.(http.Flusher); ok {
		fw.Flush()
	}

	b := pool.GetWithSize(s.options.readBufferSize)
	defer pool.Put(b)

	bw := bufio.NewWriterSize(w, 16*1024)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.options.readTimeout))
		n, err := conn.Read(b)
		if n > 0 {
			bw.WriteString(base64.StdEncoding.EncodeToString(b[:n]))
			bw.WriteByte('\n')
			if err := bw.Flush(); err != nil {
				return
			}
			if fw, ok := w.(http.Flusher); ok {
				fw.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				b[0] = '\n'
				_, _ = w.Write(b[:1])
			} else if errors.Is(err, io.EOF) {
				s.conns.Delete(cid)
				conn.Close()
			} else {
				if !errors.Is(err, io.ErrClosedPipe) && s.options.logger != nil {
					s.options.logger.Error("pht: pull read error: %v", err)
				}
				s.conns.Delete(cid)
				conn.Close()
			}
			return
		}
	}
}

func (s *Server) sameSourceIP(sess *phtSession, remoteAddr, op string) bool {
	reqIP, _, _ := net.SplitHostPort(remoteAddr)
	if sess.sourceIP == "" || reqIP == sess.sourceIP {
		return true
	}
	if s.options.logger != nil {
		s.options.logger.Warn("pht: %s rejected, IP mismatch: expected %s, got %s", op, sess.sourceIP, reqIP)
	}
	return false
}

func newToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func IsIPv4(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.To4() != nil
}

func authorizedBySecret(r *http.Request, secret string) bool {
	if secret == "" {
		return true
	}
	provided := r.Header.Get("X-PHT-Secret")
	if len(provided) != len(secret) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) == 1
}
