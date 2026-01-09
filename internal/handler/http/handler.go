package http

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httputil"
	"strings"
	"sync"

	"golang.org/x/net/http2"

	"forward/internal/auth"
	"forward/internal/config"
	"forward/internal/dialer"
	inet "forward/internal/io/net"
	"forward/internal/logging"
	"forward/internal/utils"
)

type Handler struct {
	dialer      dialer.Dialer
	log         *logging.Logger
	auth        auth.Authenticator
	requireAuth bool
	insecureTLS bool
	transparent bool

	transportOnce sync.Once
	transport     *stdhttp.Transport
}

func New(cfg config.Config, d dialer.Dialer) *Handler {
	user, pass, ok := cfg.Listen.UserPass()
	return &Handler{
		dialer:      d,
		log:         cfg.Logger,
		auth:        auth.FromUserPass(user, pass),
		requireAuth: ok,
		insecureTLS: cfg.Insecure,
		transparent: strings.EqualFold(cfg.Listen.Query.Get("transparent"), "true"),
	}
}

func (h *Handler) transportClient() *stdhttp.Transport {
	h.transportOnce.Do(func() {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: h.insecureTLS,
		}
		h.transport = &stdhttp.Transport{
			Proxy:               nil,
			DialContext:         h.dialer.DialContext,
			ForceAttemptHTTP2:   true,
			TLSClientConfig:     tlsCfg,
			DisableCompression:  true,
			MaxIdleConnsPerHost: 10,
		}
		http2.ConfigureTransport(h.transport)
	})
	return h.transport
}

// ServeHTTP implements net/http Handler to support HTTP/1.1, HTTP/2, HTTP/3 entrypoints.
func (h *Handler) ServeHTTP(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	cid := utils.NewID()

	if !strings.EqualFold(r.Method, stdhttp.MethodConnect) {
		if !r.URL.IsAbs() && !h.transparent {
			writeSimple(w, stdhttp.StatusForbidden, "403 Forbidden")
			return
		}
	}

	if h.requireAuth && !h.authorize(cid, w, r) {
		return
	}

	if strings.EqualFold(r.Method, stdhttp.MethodConnect) {
		h.handleConnect(cid, w, r)
		return
	}

	h.handleForward(cid, w, r)
}

func (h *Handler) authorize(cid string, w stdhttp.ResponseWriter, r *stdhttp.Request) bool {
	user, pass, ok := parseProxyAuth(r.Header.Get("Proxy-Authorization"))
	if ok && h.auth.Check(user, pass) {
		h.log.Debug("[%s] Forward HTTP auth success for user %s", cid, user)
		return true
	}
	if h.requireAuth {
		h.log.Debug("[%s] Forward HTTP auth failed or missing credentials from %s", cid, r.RemoteAddr)
	}
	writeAuthRequired(w)
	return false
}

func (h *Handler) handleConnect(cid string, w stdhttp.ResponseWriter, r *stdhttp.Request) {
	target := r.Host
	if target == "" {
		writeSimple(w, stdhttp.StatusBadRequest, "missing host")
		return
	}
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	h.log.Info("[%s] Forward HTTP CONNECT Received connection %s --> %s", cid, r.RemoteAddr, target)
	up, err := h.dialer.DialContext(r.Context(), "tcp", target)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			(r.Context().Err() != nil && (errors.Is(r.Context().Err(), context.Canceled) || errors.Is(r.Context().Err(), context.DeadlineExceeded))) {
			h.log.Debug("[%s] Forward HTTP connect dial canceled: %v", cid, err)
		} else {
			h.log.Error("[%s] Forward HTTP connect dial error: %v", cid, err)
		}
		writeSimple(w, stdhttp.StatusForbidden, "403 Forbidden")
		return
	}

	if hj, ok := w.(stdhttp.Hijacker); ok {
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			h.log.Error("[%s] Forward HTTP connect hijack error: %v", cid, err)
			_ = up.Close()
			writeSimple(w, stdhttp.StatusInternalServerError, "hijack failed")
			return
		}
		defer conn.Close()
		defer up.Close()

		_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = bufrw.Flush()

		h.log.Debug("[%s] Forward HTTP CONNECT Connected to upstream %s --> %s", cid, r.RemoteAddr, target)

		bytes, dur, err := inet.Bidirectional(r.Context(), conn, up)
		if err != nil && r.Context().Err() == nil {
			h.log.Error("[%s] Forward HTTP connect transfer error: %v", cid, err)
		}
		h.log.Debug("[%s] Forward HTTP CONNECT Closed connection %s --> %s transferred %d bytes in %s", cid, r.RemoteAddr, target, bytes, dur)
		return
	}

	flusher, ok := w.(stdhttp.Flusher)
	if !ok {
		h.log.Error("[%s] Forward HTTP connect: response writer not flushable", cid)
		_ = up.Close()
		writeSimple(w, stdhttp.StatusInternalServerError, "stream not supported")
		return
	}

	w.WriteHeader(stdhttp.StatusOK)
	flusher.Flush()

	h.streamWithBody(r.Context(), w, r.Body, up, flusher)
}

func (h *Handler) handleForward(cid string, w stdhttp.ResponseWriter, r *stdhttp.Request) {
	h.log.Debug("[%s] Forward HTTP Received connection from %s", cid, r.RemoteAddr)

	ctx := r.Context()
	req, err := h.prepareUpstreamRequest(ctx, r)
	if err != nil {
		writeSimple(w, stdhttp.StatusBadRequest, "bad request")
		return
	}

	h.log.Info("[%s] Forward HTTP Received connection %s --> %s", cid, r.RemoteAddr, req.URL.Host)

	resp, err := h.transportClient().RoundTrip(req)
	if err != nil {
		h.log.Debug("[%s] Forward HTTP dial failed %s: %v", cid, req.URL.String(), err)
		writeSimple(w, stdhttp.StatusForbidden, err.Error())
		return
	}
	defer resp.Body.Close()

	h.log.Debug("[%s] Forward HTTP response from upstream: %s %d %s", cid, req.URL.Host, resp.StatusCode, resp.Status)

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil && ctx.Err() == nil {
		h.log.Error("[%s] Forward HTTP error: write client: %v", cid, err)
		return
	}
	h.log.Info("[%s] Forward HTTP Close %s %d %s", cid, req.URL.Host, resp.StatusCode, resp.Status)
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

func (h *Handler) streamWithBody(ctx context.Context, w stdhttp.ResponseWriter, body io.ReadCloser, upstream net.Conn, fl stdhttp.Flusher) {
	var once sync.Once
	closer := func() {
		once.Do(func() {
			upstream.Close()
			body.Close()
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
		io.Copy(upstream, body)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			// Do not fully close, as we might be reading
			// But if CloseWrite is not supported, we have to rely on context/defer
		}
	}()

	respWriter := &flushWriter{w: w, f: fl}
	io.Copy(respWriter, upstream)

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

func cleanProxyHeaders(r *stdhttp.Request) {
	// Remove standard hop-by-hop headers
	hopByHop := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
		"Proxy-Connection", // Non-standard but common
	}

	// Remove headers listed in the Connection header
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

func writeAuthRequired(w stdhttp.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="`+config.CamouflageRealm+`"`)
	writeSimple(w, stdhttp.StatusForbidden, config.CamouflagePageTitle)
}

func writeSimple(w stdhttp.ResponseWriter, status int, title string) {
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
		"Trailers":            {},
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

func dumpRequest(log *logging.Logger, r *stdhttp.Request) {
	if log == nil || log.Level() > logging.LevelDebug {
		return
	}
	if b, err := httputil.DumpRequest(r, false); err == nil {
		log.Debug("Forward HTTP request dump:\n%s", string(b))
	}
}
