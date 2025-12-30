package proxy

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"sync"

	"go-forward/core/utils"
)

// Start 启动代理服务器
func Start(listenURL string, forwardURL string) {
	scheme, auth, addr := utils.URLParse(listenURL)
	baseOpts, err := utils.BuildServerOptions(listenURL, []string{"h2", "http/1.1"})
	if err != nil {
		utils.Error("[Proxy] [Server] option error: %v", err)
		return
	}

	if scheme == "tls" {
		baseOpts.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
	}

	// 如果指定了 quic 协议，则只启动 QUIC (UDP) 监听
	if scheme == "quic" || scheme == "http3" {
		StartQUIC(addr, forwardURL, baseOpts)
		return
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		utils.Error("[Proxy] [Server] Listen error: %v", err)
		return
	}
	defer l.Close()

	utils.Info("[Proxy] [Server] Listening on %s (%s)", addr, scheme)

	if scheme == "http" || scheme == "http1.1" {
		serveHTTPListener(l, forwardURL, baseOpts)
		return
	}

	if scheme == "http2" || scheme == "https" {
		baseOpts.TLSConfig.NextProtos = []string{"h2", "http/1.1"}

		serveHTTPListener(l, forwardURL, baseOpts)
		return
	}

	dispatcher := newSniffDispatcher(l.Addr(), forwardURL, auth)
	dispatcher.Start()

	for {
		conn, err := l.Accept()
		if err != nil {
			utils.Error("[Proxy] [Server] Accept error: %v", err)
			continue
		}
		go HandleConnection(conn, forwardURL, baseOpts, dispatcher)
	}
}

func HandleConnection(conn net.Conn, forwardURL string, baseOpts *utils.ServerOptions, dispatcher *SniffDispatcher) {
	auth := baseOpts.Auth
	scheme := baseOpts.Scheme
	tlsConfig := baseOpts.TLSConfig
	authorizedKeys := baseOpts.AuthorizedKeys

	switch scheme {
	case "ssh":
		HandleSSH(conn, forwardURL, auth, authorizedKeys)
		return
	case "http", "http1.1":
		HandleHTTP1(conn, forwardURL, auth, tlsConfig)
		return
	case "http2", "https":
		HandleHTTP2(conn, forwardURL, auth, tlsConfig)
		return
	case "socks5":
		HandleSocks5(conn, forwardURL, auth)
		return
	case "tls":
		HandleTLS(conn, forwardURL, baseOpts, dispatcher)
		return
	}

	// 2. 嗅探协议类型 (用于自动检测或 scheme 为空/tcp 的情况)
	br := bufio.NewReader(conn)
	peek, _ := br.Peek(1)

	if len(peek) == 0 {
		conn.Close()
		return
	}

	// socks5
	if peek[0] == 0x05 {
		HandleSocks5(newBufferedConn(conn, br), forwardURL, auth)
		return
	}

	// https / tls
	if peek[0] == 0x16 {
		HandleTLS(newBufferedConn(conn, br), forwardURL, baseOpts, dispatcher)
		return
	}

	// ssh
	if peek[0] == 'S' {
		peek3, _ := br.Peek(3)
		if string(peek3) == "SSH" {
			HandleSSH(newBufferedConn(conn, br), forwardURL, auth, authorizedKeys)
			return
		}
	}

	// 如果不是 socks5 / ssh / tls / https 默认使用 HTTP
	if dispatcher == nil {
		HandleHTTP1(newBufferedConn(conn, br), forwardURL, auth, nil)
		return
	}
	dispatcher.ServeConn(newBufferedConn(conn, br))
}

type BufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufferedConn(c net.Conn, r *bufio.Reader) *BufferedConn {
	return &BufferedConn{Conn: c, r: r}
}

func (b *BufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *BufferedConn) ConnectionState() tls.ConnectionState {
	if tc, ok := b.Conn.(*tls.Conn); ok {
		return tc.ConnectionState()
	}
	return tls.ConnectionState{}
}

func serveHTTPListener(l net.Listener, forwardURL string, baseOpts *utils.ServerOptions) {
	handler := &ProxyHandler{
		ForwardURL: forwardURL,
		Auth:       baseOpts.Auth,
	}
	server := &http.Server{Handler: handler}

	if baseOpts.TLSConfig != nil {
		tlsListener := tls.NewListener(l, baseOpts.TLSConfig)
		if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
			utils.Error("[Proxy] [Server] HTTP server error: %v", err)
		}
		return
	}

	if err := server.Serve(l); err != nil && err != http.ErrServerClosed {
		utils.Error("[Proxy] [Server] HTTP server error: %v", err)
	}
}

type SniffDispatcher struct {
	server *http.Server
	l      *chanListener
	once   sync.Once
}

func newSniffDispatcher(addr net.Addr, forwardURL string, auth *utils.Auth) *SniffDispatcher {
	utils.Info("[Proxy] [Server] Starting HTTP sniff dispatcher on %s", addr.String())
	handler := &ProxyHandler{
		ForwardURL: forwardURL,
		Auth:       auth,
	}
	return &SniffDispatcher{
		server: &http.Server{Handler: handler},
		l:      newChanListener(addr),
	}
}

func (d *SniffDispatcher) Start() {
	d.once.Do(func() {
		go func() {
			if err := d.server.Serve(d.l); err != nil && err != http.ErrServerClosed && err != net.ErrClosed {
				utils.Error("[Proxy] [Server] HTTP sniff error: %v", err)
			}
		}()
	})
}

func (d *SniffDispatcher) ServeConn(conn net.Conn) {
	d.Start()
	if err := d.l.Push(conn); err != nil {
		conn.Close()
	}
}

type chanListener struct {
	addr      net.Addr
	ch        chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{
		addr:   addr,
		ch:     make(chan net.Conn, 128),
		closed: make(chan struct{}),
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case conn, ok := <-l.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (l *chanListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		close(l.ch)
	})
	return nil
}

func (l *chanListener) Addr() net.Addr {
	return l.addr
}

func (l *chanListener) Push(conn net.Conn) error {
	select {
	case <-l.closed:
		return net.ErrClosed
	default:
	}

	select {
	case l.ch <- conn:
		return nil
	case <-l.closed:
		return net.ErrClosed
	}
}
