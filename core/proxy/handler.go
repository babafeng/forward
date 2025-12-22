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

type ProxyHandler struct {
	ForwardURLs []string
	Auth        *utils.Auth
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var forwardInfo string
	if len(h.ForwardURLs) > 0 {
		forwardInfo = utils.RedactURL(h.ForwardURLs[0])
	} else {
		forwardInfo = "Direct"
	}
	utils.Logging("[Proxy] [Handler] Request received: %s %s --> %s via %v", r.Method, r.RemoteAddr, r.URL, forwardInfo)
	if r.Method != http.MethodConnect && !r.URL.IsAbs() && r.Host == "" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello World!"))
		return
	}

	if r.Method != http.MethodConnect && r.URL.Scheme == "" && strings.HasPrefix(r.RequestURI, "/") {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello World!"))
		return
	}

	if h.Auth != nil {
		authHeader := r.Header.Get("Proxy-Authorization")
		if authHeader == "" {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
			http.Error(w, "Authentication Required", http.StatusProxyAuthRequired)
			utils.Logging("[Proxy] [Handler] Request Authentication Required: %s %s --> %s via %v", r.Method, r.RemoteAddr, r.URL, forwardInfo)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Basic" {
			http.Error(w, "Authentication Required", http.StatusProxyAuthRequired)
			utils.Logging("[Proxy] [Handler] Request Authentication Required: %s %s --> %s via %v", r.Method, r.RemoteAddr, r.URL, forwardInfo)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			http.Error(w, "Authentication Required", http.StatusProxyAuthRequired)
			utils.Logging("[Proxy] [Handler] Request Authentication Required: %s %s --> %s via %v", r.Method, r.RemoteAddr, r.URL, forwardInfo)
			return
		}

		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 || !h.Auth.Validate(pair[0], pair[1]) {
			http.Error(w, "Authentication Required", http.StatusProxyAuthRequired)
			utils.Logging("[Proxy] [Handler] Request Authentication Required: %s %s --> %s via %v", r.Method, r.RemoteAddr, r.URL, forwardInfo)
			return
		}
	}

	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}

	h.handleHTTP(w, r)
}

func (h *ProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := Dial("tcp", r.Host, h.ForwardURLs)
	if err != nil {
		utils.Error("[Proxy] [HTTP] Dial error: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	if hijacker, ok := w.(http.Hijacker); ok {
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			utils.Error("[Proxy] [HTTP] Hijack error: %v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer clientConn.Close()

		clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		// 转发数据
		utils.Transfer(clientConn, destConn, r.Host, "Proxy", "HTTPS(H1)")
		return
	}

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	start := time.Now()
	var uploaded, downloaded int64
	done := make(chan struct{})
	go func() {
		uploaded, _ = io.Copy(destConn, r.Body)
		destConn.Close()
		close(done)
	}()

	downloaded, _ = io.Copy(w, destConn)
	<-done

	duration := time.Since(start)
	total := uploaded + downloaded
	utils.Info("[Proxy] [HTTPS(H2/H3)] %s --> %s %d bytes %v", r.RemoteAddr, r.Host, total, duration)
}

func (h *ProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	var forwardInfo string
	if len(h.ForwardURLs) > 0 {
		forwardInfo = utils.RedactURL(h.ForwardURLs[0])
	} else {
		forwardInfo = "Direct"
	}
	utils.Info("[Proxy] [HTTP] %s %s --> %s via %v", r.Method, r.RemoteAddr, r.URL, forwardInfo)
	delHopHeaders(r.Header)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return Dial(network, addr, h.ForwardURLs)
		},
	}

	r.RequestURI = ""

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

	delHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

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
