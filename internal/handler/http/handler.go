package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"forward/base/auth"
	inet "forward/base/io/net"
	"forward/base/logging"
	"forward/internal/chain"
	"forward/internal/config"
	ictx "forward/internal/ctx"
	corehandler "forward/internal/handler"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/router"
)

func init() {
	registry.HandlerRegistry().Register("http", NewHandler)
}

type Handler struct {
	options        corehandler.Options
	auth           auth.Authenticator
	requireAuth    bool
	transparent    bool
	insecureTLS    bool
	enableUDP      bool
	udpIdle        time.Duration
	maxUDPSessions int

	transportOnce sync.Once
	transport     *stdhttp.Transport
}

type routeContextKey int

const routeKey routeContextKey = iota

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
		options:        options,
		auth:           auth.FromUserPass(user, pass),
		requireAuth:    requireAuth,
		enableUDP:      true,
		udpIdle:        config.DefaultUDPIdleTimeout,
		maxUDPSessions: config.DefaultMaxUDPSessions,
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
	if v := md.Get("transparent"); v != nil {
		h.transparent = parseBool(v)
	}
	if v := md.Get("insecure"); v != nil {
		h.insecureTLS = parseBool(v)
	}
	if v := md.Get("udp"); v != nil {
		h.enableUDP = parseBool(v)
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
	h.logf(logging.LevelInfo, "HTTP connection %s -> %s", remote, local)

	if md := ictx.MetadataFromContext(ctx); md != nil {
		if w, ok := md.Get(metadata.MetaHTTPResponseWriter).(stdhttp.ResponseWriter); ok && w != nil {
			if r, ok := md.Get(metadata.MetaHTTPRequest).(*stdhttp.Request); ok && r != nil {
				h.ServeHTTP(w, r)
				return nil
			}
		}
	}

	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return err
		}
		if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
			h2srv := &http2.Server{}
			h2srv.ServeConn(tlsConn, &http2.ServeConnOpts{
				Context: ctx,
				Handler: stdhttp.HandlerFunc(h.ServeHTTP),
			})
			return nil
		}
	}

	// Use http.Server for HTTP/1.x to handle timeouts and limits correctly
	server := &stdhttp.Server{
		Handler:           stdhttp.HandlerFunc(h.ServeHTTP),
		ReadHeaderTimeout: 30 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
		IdleTimeout:       60 * time.Second,
		BaseContext: func(l net.Listener) context.Context {
			return ctx
		},
	}

	// Track connection close to avoid premature return
	done := make(chan struct{})
	wrappedConn := &closeNotifyConn{
		Conn: conn,
		onClose: func() {
			select {
			case <-done:
			default:
				close(done)
			}
		},
	}

	ln := &oneShotListener{conn: wrappedConn, addr: conn.LocalAddr()}

	// serve in background (it will return quickly due to one-shot listener)
	go func() {
		_ = server.Serve(ln)
	}()

	// Wait for connection to be closed by http.Server (IdleTimeout) or Hijacker
	select {
	case <-done:
	case <-ctx.Done():
		server.Close()
	}

	return nil
}

type closeNotifyConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *closeNotifyConn) Close() error {
	c.once.Do(c.onClose)
	return c.Conn.Close()
}

type oneShotListener struct {
	conn net.Conn
	addr net.Addr
	mu   sync.Mutex
	done bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return nil, net.ErrClosed
	}
	l.done = true
	return l.conn, nil
}

func (l *oneShotListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.done = true
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.addr
}

// ServeHTTP handles HTTP/1.1, HTTP/2, and HTTP/3 proxy requests when bridged via listener metadata.
func (h *Handler) ServeHTTP(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	h.logf(logging.LevelInfo, "HTTP request %s %s from %s host=%s", r.Method, redactURL(r.URL), r.RemoteAddr, r.Host)

	if !strings.EqualFold(r.Method, stdhttp.MethodConnect) {
		if isUDPRequest(r) {
			if hj, ok := w.(stdhttp.Hijacker); ok {
				conn, bufrw, err := hj.Hijack()
				if err != nil {
					h.logf(logging.LevelError, "HTTP UDP hijack error: %v", err)
					writeSimpleHTTP(w, stdhttp.StatusInternalServerError, "hijack failed")
					return
				}
				// We don't close conn here, handleUDP will manage it
				h.handleUDP(r.Context(), conn, bufrw.Reader)
				return
			}
		}

		if !r.URL.IsAbs() && !h.transparent {
			h.logf(logging.LevelDebug, "HTTP reject non-absolute request from %s: %s", r.RemoteAddr, r.URL.String())
			writeSimpleHTTP(w, stdhttp.StatusForbidden, config.CamouflagePageTitle)
			return
		}
	}

	if h.requireAuth && !h.authorizeHTTP(w, r) {
		return
	}

	if strings.EqualFold(r.Method, stdhttp.MethodConnect) {
		h.handleConnectHTTP(w, r)
		return
	}

	h.handleForwardHTTP(w, r)
}

func (h *Handler) authorizeHTTP(w stdhttp.ResponseWriter, r *stdhttp.Request) bool {
	user, pass, ok := parseProxyAuth(r.Header.Get("Proxy-Authorization"))
	if ok && h.auth.Check(user, pass) {
		h.logf(logging.LevelDebug, "HTTP auth success for user %s", user)
		return true
	}
	h.logf(logging.LevelDebug, "HTTP auth failed or missing credentials from %s", r.RemoteAddr)
	writeAuthRequiredHTTP(w)
	return false
}

func (h *Handler) handleConnectHTTP(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	target := r.Host
	if target == "" {
		writeSimpleHTTP(w, stdhttp.StatusBadRequest, "missing host")
		return
	}
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	ctx := r.Context()
	route, err := h.options.Router.Route(ctx, "tcp", target)
	if err != nil {
		h.logf(logging.LevelError, "HTTP route error: %v", err)
		writeSimpleHTTP(w, stdhttp.StatusForbidden, config.CamouflagePageTitle)
		return
	}
	if route == nil {
		route = chain.NewRoute()
	}
	h.logf(logging.LevelDebug, "HTTP CONNECT route via %s", routeSummary(route))

	h.logf(logging.LevelInfo, "HTTP CONNECT %s -> %s", r.RemoteAddr, target)
	up, err := route.Dial(ctx, "tcp", target)
	if err != nil {
		h.logf(logging.LevelError, "HTTP connect dial error: %v", err)
		writeSimpleHTTP(w, stdhttp.StatusForbidden, config.CamouflagePageTitle)
		return
	}
	defer up.Close()

	if hj, ok := w.(stdhttp.Hijacker); ok {
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			h.logf(logging.LevelError, "HTTP connect hijack error: %v", err)
			writeSimpleHTTP(w, stdhttp.StatusInternalServerError, "hijack failed")
			return
		}
		defer conn.Close()

		_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = bufrw.Flush()

		bytes, dur, err := inet.Bidirectional(ctx, conn, up)
		h.logf(logging.LevelInfo, "HTTP CONNECT closed %s -> %s bytes=%d dur=%s", r.RemoteAddr, target, bytes, dur)
		if err != nil {
			h.logf(logging.LevelDebug, "HTTP CONNECT stream error: %v", err)
		}
		return
	}

	fl, ok := w.(stdhttp.Flusher)
	if !ok {
		h.logf(logging.LevelError, "HTTP connect: response writer not flushable")
		writeSimpleHTTP(w, stdhttp.StatusInternalServerError, "stream not supported")
		return
	}

	if err := stdhttp.NewResponseController(w).EnableFullDuplex(); err != nil {
		h.logf(logging.LevelDebug, "HTTP connect: enable full-duplex failed: %v", err)
	}

	w.WriteHeader(stdhttp.StatusOK)
	fl.Flush()

	h.streamWithBody(ctx, w, r.Body, up, fl)
	h.logf(logging.LevelInfo, "HTTP CONNECT closed %s -> %s", r.RemoteAddr, target)
}

func (h *Handler) handleForwardHTTP(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	ctx := r.Context()
	req, err := h.prepareUpstreamRequest(ctx, r)
	if err != nil {
		h.logf(logging.LevelDebug, "HTTP bad request from %s: %v", r.RemoteAddr, err)
		writeSimpleHTTP(w, stdhttp.StatusBadRequest, "bad request")
		return
	}

	target := req.URL.Host
	route, err := h.options.Router.Route(ctx, "tcp", target)
	if err != nil {
		h.logf(logging.LevelError, "HTTP route error: %v", err)
		writeSimpleHTTP(w, stdhttp.StatusForbidden, config.CamouflagePageTitle)
		return
	}
	if route == nil {
		route = chain.NewRoute()
	}
	h.logf(logging.LevelDebug, "HTTP route via %s", routeSummary(route))
	req = req.WithContext(context.WithValue(req.Context(), routeKey, route))

	h.logf(logging.LevelInfo, "HTTP %s %s -> %s", r.Method, r.URL.String(), target)
	resp, err := h.transportClient().RoundTrip(req)
	if err != nil {
		h.logf(logging.LevelDebug, "HTTP dial failed %s: %v", req.URL.String(), err)
		writeSimpleHTTP(w, stdhttp.StatusForbidden, config.CamouflagePageTitle)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil && ctx.Err() == nil {
		h.logf(logging.LevelError, "HTTP error writing response: %v", err)
		return
	}
	h.logf(logging.LevelInfo, "HTTP response %s -> %s %d", r.RemoteAddr, target, resp.StatusCode)
}

func (h *Handler) streamWithBody(ctx context.Context, w stdhttp.ResponseWriter, body io.ReadCloser, upstream net.Conn, fl stdhttp.Flusher) {
	if body == nil {
		body = io.NopCloser(strings.NewReader(""))
	}
	var once sync.Once
	closer := func() {
		once.Do(func() {
			_ = upstream.Close()
			_ = body.Close()
		})
	}
	defer closer()

	doneCh := make(chan struct{})
	defer close(doneCh)

	go func() {
		select {
		case <-ctx.Done():
			closer()
		case <-doneCh:
		}
	}()

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		_, _ = io.Copy(upstream, body)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	respWriter := &flushWriter{w: w, f: fl}
	_, _ = io.Copy(respWriter, upstream)

	select {
	case <-clientDone:
	case <-ctx.Done():
	}
}

type flushWriter struct {
	w io.Writer
	f stdhttp.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err == nil {
		fw.f.Flush()
	}
	return n, err
}

func (h *Handler) authorize(conn net.Conn, req *stdhttp.Request) bool {
	user, pass, ok := parseProxyAuth(req.Header.Get("Proxy-Authorization"))
	if ok && h.auth.Check(user, pass) {
		h.logf(logging.LevelDebug, "HTTP auth success for user %s", user)
		return true
	}
	h.logf(logging.LevelDebug, "HTTP auth failed or missing credentials from %s", req.RemoteAddr)
	writeAuthRequired(conn)
	return false
}

func (h *Handler) handleConnect(ctx context.Context, conn net.Conn, br *bufio.Reader, req *stdhttp.Request) error {
	target := req.Host
	if target == "" {
		return writeSimple(conn, stdhttp.StatusBadRequest, "missing host", nil)
	}
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	route, err := h.options.Router.Route(ctx, "tcp", target)
	if err != nil {
		h.logf(logging.LevelError, "HTTP route error: %v", err)
		return writeSimple(conn, stdhttp.StatusForbidden, config.CamouflagePageTitle, nil)
	}
	if route == nil {
		route = chain.NewRoute()
	}
	h.logf(logging.LevelDebug, "HTTP CONNECT route via %s", routeSummary(route))

	h.logf(logging.LevelInfo, "HTTP CONNECT %s -> %s", req.RemoteAddr, target)
	up, err := route.Dial(ctx, "tcp", target)
	if err != nil {
		h.logf(logging.LevelError, "HTTP connect dial error: %v", err)
		return writeSimple(conn, stdhttp.StatusForbidden, config.CamouflagePageTitle, nil)
	}
	defer up.Close()

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}

	if br != nil && br.Buffered() > 0 {
		buf, _ := br.Peek(br.Buffered())
		if len(buf) > 0 {
			_, _ = up.Write(buf)
			_, _ = br.Discard(len(buf))
		}
	}

	bytes, dur, err := inet.Bidirectional(ctx, conn, up)
	h.logf(logging.LevelInfo, "HTTP CONNECT closed %s -> %s bytes=%d dur=%s", req.RemoteAddr, target, bytes, dur)
	return err
}

func (h *Handler) handleForward(ctx context.Context, conn net.Conn, req *stdhttp.Request) (bool, error) {
	if !strings.EqualFold(req.Method, stdhttp.MethodConnect) {
		if !req.URL.IsAbs() && !h.transparent {
			return false, writeSimple(conn, stdhttp.StatusForbidden, config.CamouflagePageTitle, nil)
		}
	}

	upReq, err := h.prepareUpstreamRequest(ctx, req)
	if err != nil {
		return false, writeSimple(conn, stdhttp.StatusBadRequest, "bad request", nil)
	}

	target := upReq.URL.Host
	route, err := h.options.Router.Route(ctx, "tcp", target)
	if err != nil {
		h.logf(logging.LevelError, "HTTP route error: %v", err)
		return false, writeSimple(conn, stdhttp.StatusForbidden, config.CamouflagePageTitle, nil)
	}
	if route == nil {
		route = chain.NewRoute()
	}
	h.logf(logging.LevelDebug, "HTTP route via %s", routeSummary(route))
	upReq = upReq.WithContext(context.WithValue(upReq.Context(), routeKey, route))

	h.logf(logging.LevelInfo, "HTTP %s %s -> %s", req.Method, req.URL.String(), target)
	resp, err := h.transportClient().RoundTrip(upReq)
	if err != nil {
		h.logf(logging.LevelDebug, "HTTP dial failed %s: %v", upReq.URL.String(), err)
		return false, writeSimple(conn, stdhttp.StatusForbidden, config.CamouflagePageTitle, nil)
	}
	defer resp.Body.Close()

	cleanHopHeaders(resp.Header)
	resp.Close = req.Close

	bw := bufio.NewWriter(conn)
	if err := resp.Write(bw); err != nil {
		return false, err
	}
	if err := bw.Flush(); err != nil {
		return false, err
	}

	h.logf(logging.LevelInfo, "HTTP response %s -> %s %d", req.RemoteAddr, target, resp.StatusCode)
	return !req.Close && !resp.Close, nil
}

func (h *Handler) transportClient() *stdhttp.Transport {
	h.transportOnce.Do(func() {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: h.insecureTLS,
		}
		h.transport = &stdhttp.Transport{
			Proxy:               nil,
			DialContext:         h.routeDialContext,
			ForceAttemptHTTP2:   true,
			TLSClientConfig:     tlsCfg,
			DisableCompression:  true,
			MaxIdleConnsPerHost: 10,
		}
		_ = http2.ConfigureTransport(h.transport)
	})
	return h.transport
}

func (h *Handler) routeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	route, _ := ctx.Value(routeKey).(chain.Route)
	if route == nil {
		route = chain.NewRoute()
	}
	return route.Dial(ctx, network, address)
}

func (h *Handler) prepareUpstreamRequest(ctx context.Context, r *stdhttp.Request) (*stdhttp.Request, error) {
	cleanProxyHeaders(r)

	req := r.Clone(ctx)
	req.RequestURI = ""

	if !req.URL.IsAbs() {
		if !h.transparent {
			return nil, fmt.Errorf("absolute-form required")
		}
		if req.Host == "" {
			return nil, fmt.Errorf("missing host")
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		return req, nil
	}
	if req.URL.Host == "" {
		return nil, fmt.Errorf("missing host")
	}
	return req, nil
}

func parseProxyAuth(v string) (string, string, bool) {
	if v == "" {
		return "", "", false
	}
	parts := strings.SplitN(v, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "basic") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", false
	}
	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		return "", "", false
	}
	return creds[0], creds[1], true
}

func writeAuthRequiredHTTP(w stdhttp.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="`+config.CamouflageRealm+`"`)
	writeSimpleHTTP(w, stdhttp.StatusForbidden, config.CamouflagePageTitle)
}

func writeSimpleHTTP(w stdhttp.ResponseWriter, status int, title string) {
	statusText := stdhttp.StatusText(status)
	if statusText == "" {
		statusText = "Error"
	}
	if title == "" {
		title = statusText
	}

	body := fmt.Sprintf(config.CamouflagePageBody, title, title)

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func copyHeaders(dst, src stdhttp.Header) {
	hopByHop := map[string]struct{}{
		"Connection":          {},
		"Keep-Alive":          {},
		"Proxy-Authenticate":  {},
		"Proxy-Authorization": {},
		"Te":                  {},
		"Trailer":             {},
		"Transfer-Encoding":   {},
		"Upgrade":             {},
		"Proxy-Connection":    {},
	}
	connectionTokens := map[string]struct{}{}
	if c := src.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				connectionTokens[stdhttp.CanonicalHeaderKey(f)] = struct{}{}
			}
		}
	}
	for k, vv := range src {
		if _, skip := hopByHop[k]; skip {
			continue
		}
		if _, skip := connectionTokens[k]; skip {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func writeAuthRequired(conn net.Conn) error {
	headers := map[string]string{
		"Proxy-Authenticate": `Basic realm="` + config.CamouflageRealm + `"`,
	}
	return writeSimple(conn, stdhttp.StatusForbidden, config.CamouflagePageTitle, headers)
}

func writeSimple(conn net.Conn, status int, title string, extraHeaders map[string]string) error {
	statusText := stdhttp.StatusText(status)
	if statusText == "" {
		statusText = "Error"
	}
	if title == "" {
		title = statusText
	}

	body := fmt.Sprintf(config.CamouflagePageBody, title, title)
	resp := &stdhttp.Response{
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
		Header:        make(stdhttp.Header),
	}
	resp.Header.Set("Content-Type", "text/html")
	resp.Header.Set("Connection", "close")
	for k, v := range extraHeaders {
		resp.Header.Set(k, v)
	}

	bw := bufio.NewWriter(conn)
	if err := resp.Write(bw); err != nil {
		return err
	}
	return bw.Flush()
}

func cleanProxyHeaders(r *stdhttp.Request) {
	hopByHop := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Proxy-Connection",
	}

	if c := r.Header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				r.Header.Del(f)
			}
		}
	}

	for _, h := range hopByHop {
		r.Header.Del(h)
	}
}

func cleanHopHeaders(h stdhttp.Header) {
	hopByHop := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"Proxy-Connection",
	}

	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}

	for _, name := range hopByHop {
		h.Del(name)
	}
}

func parseBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true") || t == "1"
	default:
		return false
	}
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

func routeSummary(rt chain.Route) string {
	if rt == nil {
		return "DIRECT"
	}
	nodes := rt.Nodes()
	if len(nodes) == 0 {
		return "DIRECT"
	}
	parts := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if node == nil {
			continue
		}
		name := node.Name
		if name == "" {
			name = node.Addr
		} else if node.Addr != "" && name != node.Addr {
			name = name + "(" + node.Addr + ")"
		}
		parts = append(parts, name)
	}
	if len(parts) == 0 {
		return "DIRECT"
	}
	return strings.Join(parts, " -> ")
}

// redactURL 移除 URL 中的敏感信息（userinfo 和敏感 query 参数）
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	// 复制 URL 避免修改原始对象
	redacted := *u
	redacted.User = nil

	// 脱敏敏感 query 参数
	sensitiveKeys := []string{
		"password", "pwd", "pass", "passwd",
		"token", "auth", "key", "secret",
		"psk", "session", "credential", "api_key",
	}
	if redacted.RawQuery != "" {
		q := redacted.Query()
		for _, k := range sensitiveKeys {
			if q.Has(k) {
				q.Set(k, "[REDACTED]")
			}
		}
		redacted.RawQuery = q.Encode()
	}
	return redacted.String()
}
