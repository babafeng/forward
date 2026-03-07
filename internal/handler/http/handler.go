package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
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
	options           corehandler.Options
	auth              auth.Authenticator
	requireAuth       bool
	transparent       bool
	insecureTLS       bool
	enableUDP         bool
	udpIdle           time.Duration
	maxUDPSessions    int
	readHeaderTimeout time.Duration
	maxHeaderBytes    int
	idleTimeout       time.Duration
	maxIdleConns      int
	maxIdlePerHost    int
	maxConnsPerHost   int

	transportOnce   sync.Once
	transport       *stdhttp.Transport
	http1ServerOnce sync.Once
	http1Server     *stdhttp.Server
}

type routeContextKey int

const routeKey routeContextKey = iota

type connInfo struct {
	remote string
	local  string
}

type connInfoKey struct{}

var streamNoHalfCloseGrace = 3 * time.Second

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
		options:           options,
		auth:              auth.FromUserPass(user, pass),
		requireAuth:       requireAuth,
		enableUDP:         true,
		udpIdle:           config.DefaultUDPIdleTimeout,
		maxUDPSessions:    config.DefaultMaxUDPSessions,
		readHeaderTimeout: config.DefaultReadHeaderTimeout,
		maxHeaderBytes:    config.DefaultMaxHeaderBytes,
		idleTimeout:       config.DefaultIdleTimeout,
		maxIdleConns:      config.DefaultHTTPMaxIdleConns,
		maxIdlePerHost:    config.DefaultHTTPMaxIdleConnsPerHost,
		maxConnsPerHost:   config.DefaultHTTPMaxConnsPerHost,
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

	if v := md.Get("read_header_timeout"); v != nil {
		if t, ok := v.(time.Duration); ok && t > 0 {
			h.readHeaderTimeout = t
		}
	}
	if v := md.Get("max_header_bytes"); v != nil {
		if n, ok := v.(int); ok && n > 0 {
			h.maxHeaderBytes = n
		}
	}
	if v := md.Get("idle_timeout"); v != nil {
		if t, ok := v.(time.Duration); ok && t > 0 {
			h.idleTimeout = t
		}
	}
	if v := md.Get("max_idle_conns"); v != nil {
		if n, ok := v.(int); ok && n > 0 {
			h.maxIdleConns = n
		}
	}
	if v := md.Get("max_idle_conns_per_host"); v != nil {
		if n, ok := v.(int); ok && n > 0 {
			h.maxIdlePerHost = n
		}
	}
	if v := md.Get("max_conns_per_host"); v != nil {
		if n, ok := v.(int); ok && n > 0 {
			h.maxConnsPerHost = n
		}
	}
	return nil
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn, _ ...corehandler.HandleOption) error {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	local := conn.LocalAddr().String()
	ctx = context.WithValue(ctx, connInfoKey{}, connInfo{remote: remote, local: local})
	if h.options.Logger != nil {
		h.options.Logger.Debug("%sHTTP accept %s -> %s", h.tracePrefix(ctx), remote, local)
	}
	h.debugVerbose(ctx, "%sHTTP accept %s -> %s", h.tracePrefix(ctx), remote, local)

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

	// HTTP/1.x path: reuse a shared server instance to avoid per-connection
	// server object creation on the hot path.
	cctx := &contextConn{Conn: conn, ctx: ctx}
	done := make(chan struct{})
	var doneOnce sync.Once
	closeDone := func() {
		doneOnce.Do(func() {
			close(done)
		})
	}
	wrappedConn := &closeNotifyConn{
		Conn:    cctx,
		onClose: closeDone,
	}
	ln := &oneShotListener{
		conn:      wrappedConn,
		addr:      conn.LocalAddr(),
		done:      done,
		closeDone: closeDone,
	}

	go func() {
		select {
		case <-ctx.Done():
			_ = wrappedConn.Close()
		case <-done:
		}
	}()

	err := h.http1ServerForHandle().Serve(ln)
	closeDone()
	if err == nil {
		return nil
	}
	if errors.Is(err, stdhttp.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}

type contextConn struct {
	net.Conn
	ctx context.Context
}

func (c *contextConn) Context() context.Context {
	return c.ctx
}

type closeNotifyConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *closeNotifyConn) Context() context.Context {
	if cc, ok := c.Conn.(interface{ Context() context.Context }); ok {
		return cc.Context()
	}
	return context.Background()
}

func (c *closeNotifyConn) Close() error {
	if c.onClose != nil {
		c.once.Do(c.onClose)
	}
	return c.Conn.Close()
}

func (h *Handler) http1ServerForHandle() *stdhttp.Server {
	h.http1ServerOnce.Do(func() {
		h.http1Server = &stdhttp.Server{
			Handler:           stdhttp.HandlerFunc(h.ServeHTTP),
			ReadHeaderTimeout: h.readHeaderTimeout,
			MaxHeaderBytes:    h.maxHeaderBytes,
			IdleTimeout:       h.idleTimeout,
			ConnContext: func(base context.Context, c net.Conn) context.Context {
				if cc, ok := c.(interface{ Context() context.Context }); ok {
					if ctx := cc.Context(); ctx != nil {
						return ctx
					}
				}
				return base
			},
		}
	})
	return h.http1Server
}

type oneShotListener struct {
	conn      net.Conn
	addr      net.Addr
	done      <-chan struct{}
	closeDone func()

	mu       sync.Mutex
	accepted bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.accepted {
		l.accepted = true
		conn := l.conn
		l.mu.Unlock()
		return conn, nil
	}
	done := l.done
	l.mu.Unlock()

	if done != nil {
		<-done
	}
	return nil, net.ErrClosed
}

func (l *oneShotListener) Close() error {
	if l.closeDone != nil {
		l.closeDone()
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.addr
}

// ServeHTTP handles HTTP/1.1, HTTP/2, and HTTP/3 proxy requests when bridged via listener metadata.
func (h *Handler) ServeHTTP(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	prefix := h.tracePrefix(r.Context())
	h.debugVerbose(r.Context(), "%sHTTP request %s %s from %s host=%s", prefix, r.Method, redactURL(r.URL), r.RemoteAddr, r.Host)

	if isUDPRequest(r) {
		if !strings.EqualFold(r.Method, stdhttp.MethodConnect) {
			writeSimpleHTTP(w, stdhttp.StatusBadRequest, "bad udp request")
			return
		}
		if hj, ok := w.(stdhttp.Hijacker); ok {
			conn, bufrw, err := hj.Hijack()
			if err != nil {
				h.options.Logger.Error("HTTP UDP hijack error: %v", err)
				writeSimpleHTTP(w, stdhttp.StatusInternalServerError, "hijack failed")
				return
			}
			h.handleUDP(r.Context(), conn, bufrw.Reader)
			return
		}
	}

	if !strings.EqualFold(r.Method, stdhttp.MethodConnect) {
		if !r.URL.IsAbs() && !h.transparent {
			h.options.Logger.Debug("%sHTTP reject non-absolute request from %s: %s", prefix, r.RemoteAddr, r.URL.String())
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
	prefix := h.tracePrefix(r.Context())
	user, pass, ok := parseProxyAuth(r.Header.Get("Proxy-Authorization"))
	if ok && h.auth.Check(user, pass) {
		h.debugVerbose(r.Context(), "%sHTTP auth success for user %s", prefix, user)
		return true
	}
	h.options.Logger.Debug("%sHTTP auth failed or missing credentials from %s", prefix, r.RemoteAddr)
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
	start := time.Now()
	prefix := h.tracePrefix(ctx)
	h.logHTTPConnectionInfo(ctx, r.RemoteAddr, target)
	route, err := h.options.Router.Route(ctx, "tcp", target)
	if err != nil {
		h.options.Logger.Error("HTTP Route error: %v", err)
		writeSimpleHTTP(w, stdhttp.StatusForbidden, config.CamouflagePageTitle)
		return
	}
	if route == nil {
		route = chain.NewRoute()
	}
	h.logHTTPConnectionDebug(ctx, r.RemoteAddr, target, route)
	up, err := route.Dial(ctx, "tcp", target)
	if err != nil {
		h.options.Logger.Error("HTTP connect dial error: %v", err)
		writeSimpleHTTP(w, stdhttp.StatusForbidden, config.CamouflagePageTitle)
		return
	}
	defer up.Close()

	if hj, ok := w.(stdhttp.Hijacker); ok {
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			h.options.Logger.Error("HTTP connect hijack error: %v", err)
			writeSimpleHTTP(w, stdhttp.StatusInternalServerError, "hijack failed")
			return
		}
		defer conn.Close()

		_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = bufrw.Flush()

		bytes, dur, streamErr := inet.Bidirectional(ctx, conn, up)
		if streamErr != nil && ctx.Err() == nil {
			h.options.Logger.Debug("%sHTTP CONNECT closed %s -> %s bytes=%d dur=%s err=%v", prefix, r.RemoteAddr, target, bytes, dur, streamErr)
		} else {
			h.options.Logger.Debug("%sHTTP CONNECT closed %s -> %s bytes=%d dur=%s", prefix, r.RemoteAddr, target, bytes, dur)
		}
		return
	}

	fl, ok := w.(stdhttp.Flusher)
	if !ok {
		h.options.Logger.Error("HTTP connect: response writer not flushable")
		writeSimpleHTTP(w, stdhttp.StatusInternalServerError, "stream not supported")
		return
	}

	if err := stdhttp.NewResponseController(w).EnableFullDuplex(); err != nil {
		h.debugVerbose(ctx, "%sHTTP connect: enable full-duplex failed: %v", prefix, err)
	}

	w.WriteHeader(stdhttp.StatusOK)
	fl.Flush()

	h.streamWithBody(ctx, w, r.Body, up, fl)
	h.options.Logger.Debug("%sHTTP CONNECT closed %s -> %s dur=%s", prefix, r.RemoteAddr, target, time.Since(start))
}

func (h *Handler) handleForwardHTTP(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	ctx := r.Context()
	start := time.Now()
	prefix := h.tracePrefix(ctx)
	req, err := h.prepareUpstreamRequest(ctx, r)
	if err != nil {
		h.options.Logger.Debug("%sHTTP bad request from %s: %v", prefix, r.RemoteAddr, err)
		writeSimpleHTTP(w, stdhttp.StatusBadRequest, "bad request")
		return
	}

	target := req.URL.Host
	h.logHTTPConnectionInfo(ctx, r.RemoteAddr, target)
	route, err := h.options.Router.Route(ctx, "tcp", target)
	if err != nil {
		h.options.Logger.Error("HTTP Route error: %v", err)
		writeSimpleHTTP(w, stdhttp.StatusForbidden, config.CamouflagePageTitle)
		return
	}
	if route == nil {
		route = chain.NewRoute()
	}
	h.logHTTPConnectionDebug(ctx, r.RemoteAddr, target, route)
	req = req.WithContext(context.WithValue(req.Context(), routeKey, route))

	resp, err := h.transportClient().RoundTrip(req)
	if err != nil {
		h.options.Logger.Debug("%sHTTP %s %s -> %s failed: %v dur=%s", prefix, r.Method, redactURL(r.URL), target, err, time.Since(start))
		writeSimpleHTTP(w, stdhttp.StatusForbidden, config.CamouflagePageTitle)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil && ctx.Err() == nil {
		h.options.Logger.Error("HTTP error writing response: %v", err)
		return
	}
	h.options.Logger.Debug("%sHTTP %s %s -> %s status=%d dur=%s", prefix, r.Method, redactURL(r.URL), target, resp.StatusCode, time.Since(start))
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
	ctxDone := ctx.Done()
	if ctxDone != nil {
		go func() {
			select {
			case <-ctxDone:
				closer()
			case <-doneCh:
			}
		}()
	}
	defer close(doneCh)

	clientDone := make(chan bool, 1)
	go func() {
		_, _ = io.Copy(upstream, body)
		halfClosed := false
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			halfClosed = true
		}
		clientDone <- halfClosed
	}()

	serverDone := make(chan struct{})
	respWriter := newFlushWriter(w, fl)
	go func() {
		defer close(serverDone)
		_, _ = io.Copy(respWriter, upstream)
		respWriter.Flush()
	}()

	var forceClose <-chan time.Time
	var timer *time.Timer
	for {
		select {
		case halfClosed := <-clientDone:
			clientDone = nil
			if !halfClosed {
				timer = time.NewTimer(streamNoHalfCloseGrace)
				forceClose = timer.C
			}
		case <-serverDone:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-forceClose:
			forceClose = nil
			closer()
		case <-ctxDone:
			ctxDone = nil
			closer()
		}
	}
}

type flushWriter struct {
	w             io.Writer
	f             stdhttp.Flusher
	pending       int
	lastFlush     time.Time
	maxBufferSize int
	flushInterval time.Duration
}

func newFlushWriter(w io.Writer, f stdhttp.Flusher) *flushWriter {
	return &flushWriter{
		w:             w,
		f:             f,
		lastFlush:     time.Now(),
		maxBufferSize: 128 * 1024,
		flushInterval: 100 * time.Millisecond,
	}
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if n > 0 {
		fw.pending += n
	}
	if err == nil {
		now := time.Now()
		if fw.pending >= fw.maxBufferSize || now.Sub(fw.lastFlush) >= fw.flushInterval {
			fw.f.Flush()
			fw.pending = 0
			fw.lastFlush = now
		}
	}
	return n, err
}

func (fw *flushWriter) Flush() {
	if fw.pending > 0 {
		fw.f.Flush()
		fw.pending = 0
		fw.lastFlush = time.Now()
	}
}

func (h *Handler) transportClient() *stdhttp.Transport {
	h.transportOnce.Do(func() {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: h.insecureTLS,
		}
		h.transport = &stdhttp.Transport{
			Proxy:                 nil,
			DialContext:           h.routeDialContext,
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       tlsCfg,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			DisableCompression:    true,
			MaxIdleConns:          h.maxIdleConns,
			MaxIdleConnsPerHost:   h.maxIdlePerHost,
			MaxConnsPerHost:       h.maxConnsPerHost,
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

func (h *Handler) tracePrefix(ctx context.Context) string {
	tr := ictx.TraceFromContext(ctx)
	if tr == nil {
		return ""
	}
	return tr.Prefix()
}

func (h *Handler) debugVerbose(ctx context.Context, format string, args ...any) {
	if h.options.Logger == nil {
		return
	}
	tr := ictx.TraceFromContext(ctx)
	if tr == nil || !tr.Verbose {
		return
	}
	h.options.Logger.Debug(format, args...)
}

func (h *Handler) logHTTPConnectionInfo(ctx context.Context, remote, target string) {
	if h.options.Logger == nil {
		return
	}
	remote, local := h.connectionEndpoints(ctx, remote)
	h.options.Logger.Info("%sHTTP connection %s -> %s -> %s", h.tracePrefix(ctx), remote, local, target)
}

func (h *Handler) logHTTPConnectionDebug(ctx context.Context, remote, target string, route chain.Route) {
	if h.options.Logger == nil {
		return
	}
	remote, local := h.connectionEndpoints(ctx, remote)
	h.options.Logger.Debug("%sHTTP connection %s -> %s -> %s via %s", h.tracePrefix(ctx), remote, local, target, chain.RouteSummary(route))
}

func (h *Handler) connectionEndpoints(ctx context.Context, remoteFallback string) (remote, local string) {
	remote = remoteFallback
	if info, ok := ctx.Value(connInfoKey{}).(connInfo); ok {
		if info.remote != "" {
			remote = info.remote
		}
		if info.local != "" {
			local = info.local
		}
	}
	if local == "" {
		if tr := ictx.TraceFromContext(ctx); tr != nil {
			if tr.Src != "" && remote == "" {
				remote = tr.Src
			}
			if tr.Local != "" {
				local = tr.Local
			}
		}
	}
	if remote == "" {
		remote = "unknown-remote"
	}
	if local == "" {
		local = "unknown-local"
	}
	return remote, local
}

func (h *Handler) log() *logging.Logger {
	return h.options.Logger
}

var sensitiveQueryKeys = map[string]struct{}{
	"password":   {},
	"pwd":        {},
	"pass":       {},
	"passwd":     {},
	"token":      {},
	"auth":       {},
	"key":        {},
	"secret":     {},
	"psk":        {},
	"session":    {},
	"credential": {},
	"api_key":    {},
}

// redactURL 移除 URL 中的敏感信息（userinfo 和敏感 query 参数）
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	// 复制 URL 避免修改原始对象
	redacted := *u
	redacted.User = nil

	if redacted.RawQuery != "" {
		q := redacted.Query()
		for k := range q {
			if _, ok := sensitiveQueryKeys[strings.ToLower(k)]; ok {
				q.Set(k, "[REDACTED]")
			}
		}
		redacted.RawQuery = q.Encode()
	}
	return redacted.String()
}
