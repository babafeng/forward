package h3

import (
	"bufio"
	"crypto/rand"
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
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"forward/base/logging"
	"forward/base/pool"
	phtshared "forward/base/transport/h3"
)

const (
	defaultBacklog        = 128
	defaultReadBufferSize = 32 * 1024
	defaultReadTimeout    = 10 * time.Second
)

type serverOptions struct {
	authorizePath  string
	pushPath       string
	pullPath       string
	backlog        int
	tlsEnabled     bool
	tlsConfig      *tls.Config
	readBufferSize int
	readTimeout    time.Duration
	logger         *logging.Logger
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

func LoggerServerOption(logger *logging.Logger) ServerOption {
	return func(opts *serverOptions) {
		opts.logger = logger
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
	options := serverOptions{
		authorizePath:  "/authorize",
		pushPath:       "/push",
		pullPath:       "/pull",
		backlog:        defaultBacklog,
		readBufferSize: defaultReadBufferSize,
		readTimeout:    defaultReadTimeout,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.backlog <= 0 {
		options.backlog = defaultBacklog
	}
	if options.readBufferSize <= 0 {
		options.readBufferSize = defaultReadBufferSize
	}
	if options.readTimeout <= 0 {
		options.readTimeout = defaultReadTimeout
	}

	s := &Server{
		httpServer: &http.Server{
			Addr:              addr,
			ReadHeaderTimeout: 30 * time.Second,
		},
		cqueue:  make(chan net.Conn, options.backlog),
		closed:  make(chan struct{}),
		options: options,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(options.authorizePath, s.handleAuthorize)
	mux.HandleFunc(options.pushPath, s.handlePush)
	mux.HandleFunc(options.pullPath, s.handlePull)
	s.httpServer.Handler = mux

	return s
}

func NewHTTP3Server(addr string, quicConfig *quic.Config, opts ...ServerOption) *Server {
	options := serverOptions{
		authorizePath:  "/authorize",
		pushPath:       "/push",
		pullPath:       "/pull",
		backlog:        defaultBacklog,
		readBufferSize: defaultReadBufferSize,
		readTimeout:    defaultReadTimeout,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.backlog <= 0 {
		options.backlog = defaultBacklog
	}
	if options.readBufferSize <= 0 {
		options.readBufferSize = defaultReadBufferSize
	}
	if options.readTimeout <= 0 {
		options.readTimeout = defaultReadTimeout
	}

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

func (s *Server) ListenAndServe() error {
	if s.http3Server != nil {
		network := "udp"
		if isIPv4(s.http3Server.Addr) {
			network = "udp4"
		}
		addr, err := net.ResolveUDPAddr(network, s.http3Server.Addr)
		if err != nil {
			return err
		}
		s.addr = addr
		return s.http3Server.ListenAndServe()
	}

	network := "tcp"
	if isIPv4(s.httpServer.Addr) {
		network = "tcp4"
	}

	ln, err := net.Listen(network, s.httpServer.Addr)
	if err != nil {
		return err
	}

	s.addr = ln.Addr()
	if s.options.tlsEnabled {
		s.httpServer.TLSConfig = s.options.tlsConfig
		ln = tls.NewListener(ln, s.options.tlsConfig)
	}

	return s.httpServer.Serve(ln)
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
			if conn, ok := value.(net.Conn); ok {
				conn.Close()
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
	raddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if raddr == nil {
		raddr = &net.TCPAddr{}
	}

	cid := newToken()

	c1, c2 := net.Pipe()
	c := phtshared.NewServerConn(c1, s.addr, raddr)

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
	s.conns.Store(cid, c2)
}

func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
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
	conn := v.(net.Conn)

	br := bufio.NewReader(r.Body)
	data, err := br.ReadString('\n')
	if err != nil {
		if err != io.EOF && s.options.logger != nil {
			s.options.logger.Error("pht: push read error: %v", err)
		}
		conn.Close()
		s.conns.Delete(cid)
		return
	}

	data = strings.TrimSuffix(data, "\n")
	if len(data) == 0 {
		return
	}

	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		if s.options.logger != nil {
			s.options.logger.Error("pht: push decode error: %v", err)
		}
		s.conns.Delete(cid)
		conn.Close()
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})

	if _, err := conn.Write(b); err != nil {
		if s.options.logger != nil {
			s.options.logger.Error("pht: push write error: %v", err)
		}
		s.conns.Delete(cid)
		conn.Close()
		w.WriteHeader(http.StatusGone)
	}
}

func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusBadRequest)
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
	conn := v.(net.Conn)

	w.WriteHeader(http.StatusOK)
	if fw, ok := w.(http.Flusher); ok {
		fw.Flush()
	}

	b := pool.GetWithSize(s.options.readBufferSize)
	defer pool.Put(b)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.options.readTimeout))
		n, err := conn.Read(b)
		if n > 0 {
			bw := bufio.NewWriter(w)
			bw.WriteString(base64.StdEncoding.EncodeToString(b[:n]))
			bw.WriteString("\n")
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
				// closed
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

func newToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func isIPv4(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.To4() != nil
}
