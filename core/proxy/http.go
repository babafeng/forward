package proxy

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"go-forward/core/utils"
)

// HandleHTTP 处理 HTTP 代理请求
func HandleHTTP(conn net.Conn, forwardURLs []string, auth *utils.Auth) {
	// 使用 http.Server 来处理 HTTP/1.1 和 HTTP/2 请求
	server := &http.Server{
		Handler: &ProxyHandler{
			ForwardURLs: forwardURLs,
			Auth:        auth,
		},
	}

	l := &SingleConnListener{conn: conn, ch: make(chan net.Conn, 1)}
	l.ch <- conn

	server.Serve(l)
}

type ProxyHandler struct {
	ForwardURLs []string
	Auth        *utils.Auth
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	utils.Debug("[Proxy] [Handler] Request received: %s %s from %s", r.Method, r.URL, r.RemoteAddr)

	// 1. 鉴权
	if h.Auth != nil {
		authHeader := r.Header.Get("Proxy-Authorization")
		if authHeader == "" {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Basic" {
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}

		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 || !h.Auth.Validate(pair[0], pair[1]) {
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}
	}

	// 2. 处理 CONNECT 方法 (HTTPS 隧道)
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}

	// 3. 处理普通 HTTP 请求
	h.handleHTTP(w, r)
}

func (h *ProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	utils.Info("[Proxy] [HTTP] CONNECT %s", r.Host)
	destConn, err := Dial("tcp", r.Host, h.ForwardURLs)
	if err != nil {
		utils.Error("[Proxy] [HTTP] Dial error: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	// Hijack 连接 (HTTP/1.1)
	if hijacker, ok := w.(http.Hijacker); ok {
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			utils.Error("[Proxy] [HTTP] Hijack error: %v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer clientConn.Close()

		// 发送 200 Connection Established
		clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		// 转发数据
		utils.Transfer(clientConn, destConn, r.Host, "Proxy", "HTTPS(H1)")
		return
	}

	// HTTP/2 和 HTTP/3 (不支持 Hijack，使用流式传输)
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	start := time.Now()
	var uploaded, downloaded int64

	// 双向转发
	// 注意：HTTP/2+ 的 ResponseWriter 实现了 io.Writer，Request.Body 实现了 io.Reader
	// 它们对应同一个流

	done := make(chan struct{})
	go func() {
		uploaded, _ = io.Copy(destConn, r.Body)
		// 客户端关闭了写入端 (半关闭)
		// 对于 TCP 连接，我们应该关闭写入端，但 net.Conn 接口比较简单
		// 这里简单处理：关闭连接
		destConn.Close() // 这会触发下面的 Copy 退出
		close(done)
	}()

	downloaded, _ = io.Copy(w, destConn)
	<-done

	duration := time.Since(start)
	total := uploaded + downloaded
	utils.Info("[Proxy] [HTTPS(H2/H3)] %s --> %s %d bytes %v", r.RemoteAddr, r.Host, total, duration)
}

func (h *ProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	utils.Info("[Proxy] [HTTP] %s %s", r.Method, r.URL)
	// 移除 Hop-by-hop headers
	delHopHeaders(r.Header)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return Dial(network, addr, h.ForwardURLs)
		},
	}

	// RequestURI must be empty for Client.Do
	r.RequestURI = ""

	// 如果 Scheme 为空，尝试根据 Host 补全（虽然 RoundTrip 可能不需要）
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy headers
	delHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// SingleConnListener adapts a single net.Conn to net.Listener
type SingleConnListener struct {
	conn net.Conn
	ch   chan net.Conn
}

func (l *SingleConnListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	close(l.ch)
	return c, nil
}

func (l *SingleConnListener) Close() error {
	return nil
}

func (l *SingleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
