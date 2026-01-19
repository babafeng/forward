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
	"strings"
	"sync"

	"golang.org/x/net/http2"

	"forward/base/logging"
	"forward/base/auth"
	"forward/internal/chain"
	"forward/internal/config"
	corehandler "forward/internal/handler"
	inet "forward/base/io/net"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/router"
)

func init() {
	registry.HandlerRegistry().Register("http", NewHandler)
}

type Handler struct {
	options     corehandler.Options
	auth        auth.Authenticator
	requireAuth bool
	transparent bool
	insecureTLS bool

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
		options:     options,
		auth:        auth.FromUserPass(user, pass),
		requireAuth: requireAuth,
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
	return nil
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn, _ ...corehandler.HandleOption) error {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	local := conn.LocalAddr().String()
	h.logf(logging.LevelInfo, "HTTP connection %s -> %s", remote, local)

	br := bufio.NewReader(conn)
	for {
		req, err := stdhttp.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		req.RemoteAddr = remote

		if h.requireAuth && !h.authorize(conn, req) {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil
		}

		if strings.EqualFold(req.Method, stdhttp.MethodConnect) {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return h.handleConnect(ctx, conn, br, req)
		}

		keep, err := h.handleForward(ctx, conn, req)
		if req.Body != nil {
			_ = req.Body.Close()
		}
		if err != nil {
			return err
		}
		if !keep {
			return nil
		}
	}
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
