package proxy

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"sync"

	"go-forward/core/utils"

	"golang.org/x/crypto/ssh"
)

// Start 启动代理服务器
func Start(listenURL string, forwardURL string) {
	scheme, auth, addr := utils.URLParse(listenURL)

	// 解析证书参数
	var tlsConfig *tls.Config
	var authorizedKeys []ssh.PublicKey
	params := utils.ParseURLParams(listenURL)
	if params != nil {
		certFile := params.Get("cert")
		keyFile := params.Get("key")
		if certFile != "" && keyFile != "" {
			cert, err := utils.LoadCertificate(certFile, keyFile)
			if err != nil {
				utils.Error("[Proxy] [Server] Failed to load certificate: %v", err)
				return
			}
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{*cert},
				NextProtos:   []string{"h2", "http/1.1"},
			}
			utils.Info("[Proxy] [Server] Loaded certificate from %s and %s", certFile, keyFile)
		}

		pubFile := params.Get("pub")
		if pubFile != "" {
			keys, err := utils.LoadSSHAuthorizedKeys(pubFile)
			if err != nil {
				utils.Error("[Proxy] [Server] Failed to load authorized keys: %v", err)
				return
			}
			authorizedKeys = keys
			utils.Info("[Proxy] [Server] Loaded %d authorized keys from %s", len(keys), pubFile)
		}
	}

	if scheme == "tls" && tlsConfig == nil {
		cert, err := utils.GetCertificate()
		if err != nil {
			utils.Error("[Proxy] [Server] Failed to generate certificate: %v", err)
			return
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}
	}

	// 如果指定了 quic 协议，则只启动 QUIC (UDP) 监听
	if scheme == "quic" || scheme == "http3" {
		StartQUIC(addr, forwardURL, auth, tlsConfig)
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
		serveHTTPListener(l, forwardURL, auth, nil)
		return
	}

	if scheme == "http2" || scheme == "https" {
		if tlsConfig == nil {
			cert, err := utils.GetCertificate()
			if err != nil {
				utils.Error("[Proxy] [Server] Failed to generate certificate: %v", err)
				return
			}
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{*cert},
				NextProtos:   []string{"h2", "http/1.1"},
			}
		} else {
			// Ensure ALPN advertises HTTP/2.
			hasH2 := false
			hasHTTP1 := false
			for _, p := range tlsConfig.NextProtos {
				if p == "h2" {
					hasH2 = true
				}
				if p == "http/1.1" {
					hasHTTP1 = true
				}
			}
			if !hasH2 {
				tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
			}
			if !hasHTTP1 {
				tlsConfig.NextProtos = append(tlsConfig.NextProtos, "http/1.1")
			}
		}

		serveHTTPListener(l, forwardURL, auth, tlsConfig)
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
		go HandleConnection(conn, forwardURL, auth, scheme, tlsConfig, authorizedKeys, dispatcher)
	}
}

func HandleConnection(conn net.Conn, forwardURL string, auth *utils.Auth, scheme string, tlsConfig *tls.Config, authorizedKeys []ssh.PublicKey, dispatcher *SniffDispatcher) {
	// 1. 如果明确指定了协议，直接处理，不进行嗅探
	// 这样可以避免 bufio.NewReader 预读导致的数据丢失问题，
	// 也可以避免 SSH 服务端先发数据时的死锁问题。
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
		HandleTLS(conn, forwardURL, auth, tlsConfig, dispatcher)
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
		HandleTLS(newBufferedConn(conn, br), forwardURL, auth, tlsConfig, dispatcher)
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

func serveHTTPListener(l net.Listener, forwardURL string, auth *utils.Auth, tlsConfig *tls.Config) {
	handler := &ProxyHandler{
		ForwardURL: forwardURL,
		Auth:       auth,
	}
	server := &http.Server{Handler: handler}

	if tlsConfig != nil {
		tlsListener := tls.NewListener(l, tlsConfig)
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
