package http

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
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
)

type Handler struct {
	dialer      dialer.Dialer
	log         *logging.Logger
	auth        auth.Authenticator
	requireAuth bool
	insecureTLS bool

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
	}
}

func (h *Handler) transportClient() *stdhttp.Transport {
	h.transportOnce.Do(func() {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: h.insecureTLS, //nolint:gosec
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
	if h.requireAuth && !h.authorize(w, r) {
		return
	}

	if strings.EqualFold(r.Method, stdhttp.MethodConnect) {
		h.handleConnect(w, r)
		return
	}

	h.handleForward(w, r)
}

func (h *Handler) authorize(w stdhttp.ResponseWriter, r *stdhttp.Request) bool {
	user, pass, ok := parseProxyAuth(r.Header.Get("Proxy-Authorization"))
	if ok && h.auth.Check(user, pass) {
		h.log.Debug("Forward HTTP auth success for user %s", user)
		return true
	}
	if h.requireAuth {
		h.log.Debug("Forward HTTP auth failed or missing credentials from %s", r.RemoteAddr)
	}
	writeAuthRequired(w)
	return false
}

func (h *Handler) handleConnect(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	target := r.Host
	if target == "" {
		writeSimple(w, stdhttp.StatusBadRequest, "missing host")
		return
	}
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	h.log.Info("Forward HTTP CONNECT Received connection %s --> %s", r.RemoteAddr, target)
	up, err := h.dialer.DialContext(r.Context(), "tcp", target)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			(r.Context().Err() != nil && (errors.Is(r.Context().Err(), context.Canceled) || errors.Is(r.Context().Err(), context.DeadlineExceeded))) {
			h.log.Debug("Forward http connect dial canceled: %v", err)
		} else {
			h.log.Error("Forward http connect dial error: %v", err)
		}
		writeSimple(w, stdhttp.StatusBadGateway, "dial upstream failed")
		return
	}

	if hj, ok := w.(stdhttp.Hijacker); ok {
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			h.log.Error("Forward http connect hijack error: %v", err)
			_ = up.Close()
			writeSimple(w, stdhttp.StatusInternalServerError, "hijack failed")
			return
		}
		defer conn.Close()
		defer up.Close()

		_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = bufrw.Flush()

		h.log.Debug("Forward HTTP CONNECT Connected to upstream %s --> %s", r.RemoteAddr, target)

		bytes, dur, err := inet.Bidirectional(r.Context(), conn, up)
		if err != nil && r.Context().Err() == nil {
			h.log.Error("Forward http connect transfer error: %v", err)
		}
		h.log.Debug("Forward HTTP CONNECT Closed connection %s --> %s transferred %d bytes in %s", r.RemoteAddr, target, bytes, dur)
		return
	}

	flusher, ok := w.(stdhttp.Flusher)
	if !ok {
		h.log.Error("Forward http connect: response writer not flushable")
		_ = up.Close()
		writeSimple(w, stdhttp.StatusInternalServerError, "stream not supported")
		return
	}

	w.WriteHeader(stdhttp.StatusOK)
	flusher.Flush()

	h.streamWithBody(r.Context(), w, r.Body, up, flusher)
}

func (h *Handler) handleForward(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	h.log.Debug("Forward HTTP Received connection from %s", r.RemoteAddr)

	ctx := r.Context()
	req, err := h.prepareUpstreamRequest(ctx, r)
	if err != nil {
		writeSimple(w, stdhttp.StatusBadRequest, "bad request")
		return
	}

	h.log.Info("Forward HTTP Received connection %s --> %s", r.RemoteAddr, req.URL.Host)

	resp, err := h.transportClient().RoundTrip(req)
	if err != nil {
		h.log.Debug("Forward HTTP dial failed %s: %v", req.URL.String(), err)
		writeSimple(w, stdhttp.StatusBadGateway, "dial upstream failed")
		return
	}
	defer resp.Body.Close()

	h.log.Debug("Forward HTTP response from upstream: %s %d %s", req.URL.Host, resp.StatusCode, resp.Status)

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil && ctx.Err() == nil {
		h.log.Error("Forward http error: write client: %v", err)
		return
	}
	h.log.Info("Forward HTTP Close %s %d %s", req.URL.Host, resp.StatusCode, resp.Status)
}

func (h *Handler) prepareUpstreamRequest(ctx context.Context, r *stdhttp.Request) (*stdhttp.Request, error) {
	cleanProxyHeaders(r)

	req := r.Clone(ctx)
	req.RequestURI = ""

	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = r.Host
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
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")
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
	w.Header().Set("Proxy-Authenticate", `Basic realm="forward"`)
	writeSimple(w, stdhttp.StatusProxyAuthRequired, "proxy authentication required")
}

func writeSimple(w stdhttp.ResponseWriter, status int, body string) {
	statusText := stdhttp.StatusText(status)
	if statusText == "" {
		statusText = "Error"
	}
	if body == "" {
		body = statusText
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func copyHeaders(dst, src stdhttp.Header) {
	for k, vv := range src {
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
