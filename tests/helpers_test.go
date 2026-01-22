package tests

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"forward/base/endpoint"
	"forward/base/logging"
	"forward/internal/builder"
	"forward/internal/chain"
	"forward/internal/config"
	"forward/internal/handler"
	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/router"
	"forward/internal/service"

	ctls "forward/internal/config/tls"
)

type transportKind string

const (
	transportNone transportKind = ""
	transportTLS  transportKind = "tls"
	transportDTLS transportKind = "dtls"
	transportH2   transportKind = "h2"
	transportH3   transportKind = "h3"
	transportQuic transportKind = "quic"
)

func testLogger() *logging.Logger {
	return logging.New(logging.Options{Level: logging.LevelError})
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func mustParseEndpoint(t *testing.T, raw string) endpoint.Endpoint {
	t.Helper()
	ep, err := endpoint.Parse(raw)
	if err != nil {
		t.Fatalf("parse endpoint %q: %v", raw, err)
	}
	return ep
}

func buildEndpoint(t *testing.T, scheme, host string, port int, user *url.Userinfo, query url.Values) endpoint.Endpoint {
	t.Helper()
	u := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
	}
	if user != nil {
		u.User = user
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return mustParseEndpoint(t, u.String())
}

func startTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start tcp backend: %v", err)
	}
	stop := func() { _ = ln.Close() }

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return ln.Addr().String(), stop
}

func startUDPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("start udp backend: %v", err)
	}
	stop := func() { _ = conn.Close() }

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()

	return conn.LocalAddr().String(), stop
}

func splitSchemeTransport(scheme string) (base string, transport transportKind) {
	s := strings.ToLower(strings.TrimSpace(scheme))
	switch s {
	case "https":
		return "http", transportTLS
	case "http2":
		return "http2", transportNone
	case "http3":
		return "http3", transportNone
	case "quic":
		return "tcp", transportQuic
	case "tls":
		return "http", transportTLS
	case "h2":
		return "http", transportH2
	case "h3":
		return "http", transportH3
	case "dtls":
		return "tcp", transportDTLS
	case "vless", "vless+reality", "reality":
		return "vless", transportNone
	case "vless+tls":
		return "vless", transportTLS
	}
	if strings.HasSuffix(s, "+h2") {
		return strings.TrimSuffix(s, "+h2"), transportH2
	}
	if strings.HasSuffix(s, "+h3") {
		return strings.TrimSuffix(s, "+h3"), transportH3
	}
	if strings.HasSuffix(s, "+tls") {
		return strings.TrimSuffix(s, "+tls"), transportTLS
	}
	if strings.HasSuffix(s, "+dtls") {
		return strings.TrimSuffix(s, "+dtls"), transportDTLS
	}
	if strings.HasSuffix(s, "+reality") {
		return strings.TrimSuffix(s, "+reality"), transportNone
	}
	if strings.HasSuffix(s, "+quic") {
		return strings.TrimSuffix(s, "+quic"), transportQuic
	}
	return s, transportNone
}

func normalizeProxySchemes(scheme string) (handlerScheme, listenerScheme string, transport transportKind) {
	base, transport := splitSchemeTransport(scheme)
	handlerScheme = base
	listenerScheme = base

	switch base {
	case "http3":
		handlerScheme = "http"
		listenerScheme = "http3"
		return handlerScheme, listenerScheme, transportNone
	case "quic":
		handlerScheme = "tcp"
		listenerScheme = "quic"
		return handlerScheme, listenerScheme, transportNone
	case "http2":
		handlerScheme = "http"
		listenerScheme = "http2"
		return handlerScheme, listenerScheme, transportNone
	case "socks5h":
		handlerScheme = "socks5"
	case "vless":
		handlerScheme = "vless"
		listenerScheme = "reality"
		return handlerScheme, listenerScheme, transportNone
	}

	if transport == transportDTLS {
		listenerScheme = "dtls"
	}
	if transport == transportH2 {
		listenerScheme = "h2"
	}
	if transport == transportH3 {
		listenerScheme = "h3"
	}
	if transport == transportQuic {
		listenerScheme = "quic"
	}
	return
}

func buildRoute(t *testing.T, ep endpoint.Endpoint) chain.Route {
	t.Helper()
	cfg := config.Config{
		Logger:           testLogger(),
		Insecure:         true,
		DialTimeout:      3 * time.Second,
		HandshakeTimeout: 3 * time.Second,
	}
	config.ApplyDefaults(&cfg)
	rt, err := builder.BuildRoute(cfg, []endpoint.Endpoint{ep})
	if err != nil {
		t.Fatalf("build route %s: %v", ep.String(), err)
	}
	return rt
}

func dialWithRetry(t *testing.T, route chain.Route, network, address string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := route.Dial(ctx, network, address)
		if err == nil {
			return conn
		}
		cancel()
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("dial %s %s failed: %v", network, address, lastErr)
	return nil
}

func assertEcho(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("unexpected echo: got %q want %q", string(buf), string(payload))
	}
}

func assertUDPEcho(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	buf := make([]byte, len(payload))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("unexpected udp echo: got %q want %q", string(buf[:n]), string(payload))
	}
}

func startProxyServer(t *testing.T, scheme string, user *url.Userinfo, query url.Values) (endpoint.Endpoint, func()) {
	t.Helper()
	handlerScheme, listenerScheme, transport := normalizeProxySchemes(scheme)

	port := freeTCPPort(t)
	if listenerScheme == "http3" || listenerScheme == "h3" || listenerScheme == "dtls" || listenerScheme == "quic" {
		port = freeUDPPort(t)
	}

	ep := buildEndpoint(t, scheme, "127.0.0.1", port, user, query)

	cfg := config.Config{
		Listen: ep,
		Logger: testLogger(),
	}
	config.ApplyDefaults(&cfg)

	rt := router.NewStatic(chain.NewRoute())

	newListener := registry.ListenerRegistry().Get(listenerScheme)
	if newListener == nil {
		newListener = registry.ListenerRegistry().Get("tcp")
	}
	if newListener == nil {
		t.Fatalf("listener not registered for scheme %s", listenerScheme)
	}

	ctx, cancel := context.WithCancel(context.Background())
	lopts := []listener.Option{
		listener.AddrOption(ep.Address()),
		listener.LoggerOption(cfg.Logger),
		listener.RouterOption(rt),
		listener.ContextOption(ctx),
	}

	switch {
	case listenerScheme == "http3" || listenerScheme == "h3" || listenerScheme == "quic":
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{NextProtos: []string{"h3"}})
		if err != nil {
			cancel()
			t.Fatalf("http3 tls config: %v", err)
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case listenerScheme == "http2" || listenerScheme == "h2":
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{NextProtos: []string{"h2"}})
		if err != nil {
			cancel()
			t.Fatalf("http2 tls config: %v", err)
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case transport == transportTLS:
		tlsOpts := ctls.ServerOptions{}
		if handlerScheme == "http" {
			tlsOpts.NextProtos = []string{"h2", "http/1.1"}
		}
		tlsCfg, err := ctls.ServerConfig(cfg, tlsOpts)
		if err != nil {
			cancel()
			t.Fatalf("tls config: %v", err)
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case transport == transportDTLS:
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{})
		if err != nil {
			cancel()
			t.Fatalf("dtls config: %v", err)
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	}

	ln := newListener(lopts...)
	lmd := metadata.New(map[string]any{
		"handshake_timeout": cfg.HandshakeTimeout,
		metadata.KeyHost:    cfg.Listen.Host,
		metadata.KeyPort:    cfg.Listen.Port,
		metadata.KeySNI:     cfg.Listen.Query.Get("sni"),
		metadata.KeyShortID: cfg.Listen.Query.Get("sid"),
		metadata.KeyFlow:    cfg.Listen.Query.Get("flow"),
		metadata.KeyNetwork: cfg.Listen.Query.Get("type"),
		"dest":              cfg.Listen.Query.Get("dest"),
		"privatekey":        cfg.Listen.Query.Get("key"),
	})
	if cfg.Listen.User != nil {
		lmd.Set(metadata.KeyUUID, cfg.Listen.User.Username())
	}
	if err := ln.Init(lmd); err != nil {
		cancel()
		t.Fatalf("listener init %s: %v", scheme, err)
	}

	newHandler := registry.HandlerRegistry().Get(handlerScheme)
	if newHandler == nil {
		cancel()
		t.Fatalf("handler not registered for scheme %s", handlerScheme)
	}

	h := newHandler(
		handler.RouterOption(rt),
		handler.AuthOption(cfg.Listen.User),
		handler.LoggerOption(cfg.Logger),
	)
	hmd := metadata.New(map[string]any{
		"transparent":       false,
		"insecure":          cfg.Insecure,
		"handshake_timeout": cfg.HandshakeTimeout,
		"udp_idle":          cfg.UDPIdleTimeout,
		"max_udp_sessions":  cfg.MaxUDPSessions,
	})
	if err := h.Init(hmd); err != nil {
		cancel()
		t.Fatalf("handler init %s: %v", scheme, err)
	}

	if handlerScheme == "vless" && listenerScheme == "reality" {
		type validatorProvider interface {
			Validator() interface{}
		}
		type validatorSetter interface {
			SetValidator(v interface{})
		}
		if vp, ok := ln.(validatorProvider); ok {
			if vs, ok := h.(validatorSetter); ok {
				vs.SetValidator(vp.Validator())
			}
		}
	}

	stop := startService(t, ln, h, cancel)
	return ep, stop
}

func startPortForwardServer(t *testing.T, scheme, target string) (endpoint.Endpoint, func()) {
	t.Helper()
	base, transport := splitSchemeTransport(scheme)
	if base == "udp" && transport != transportNone {
		t.Fatalf("udp over %s not supported", transport)
	}

	port := freeTCPPort(t)
	if transport == transportDTLS || transport == transportH3 {
		port = freeUDPPort(t)
	}

	ep := buildEndpoint(t, scheme, "127.0.0.1", port, nil, nil)
	cfg := config.Config{
		Listen: ep,
		Logger: testLogger(),
	}
	config.ApplyDefaults(&cfg)

	rt := router.NewStatic(chain.NewRoute())

	newHandler := registry.HandlerRegistry().Get(base)
	if newHandler == nil {
		t.Fatalf("handler not registered for scheme %s", base)
	}
	h := newHandler(
		handler.RouterOption(rt),
		handler.LoggerOption(cfg.Logger),
	)
	hmd := metadata.New(map[string]any{
		"target":   target,
		"udp_idle": cfg.UDPIdleTimeout,
	})
	if err := h.Init(hmd); err != nil {
		t.Fatalf("handler init %s: %v", scheme, err)
	}

	listenerScheme := base
	switch transport {
	case transportDTLS:
		listenerScheme = "dtls"
	case transportH2:
		listenerScheme = "h2"
	case transportH3:
		listenerScheme = "h3"
	case transportQuic:
		listenerScheme = "quic"
	}

	newListener := registry.ListenerRegistry().Get(listenerScheme)
	if newListener == nil {
		t.Fatalf("listener not registered for scheme %s", listenerScheme)
	}
	ctx, cancel := context.WithCancel(context.Background())
	lopts := []listener.Option{
		listener.AddrOption(ep.Address()),
		listener.LoggerOption(cfg.Logger),
		listener.RouterOption(rt),
		listener.ContextOption(ctx),
	}
	switch transport {
	case transportTLS, transportDTLS:
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{})
		if err != nil {
			cancel()
			t.Fatalf("tls config: %v", err)
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case transportH2:
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{NextProtos: []string{"h2"}})
		if err != nil {
			cancel()
			t.Fatalf("h2 tls config: %v", err)
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case transportH3:
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{NextProtos: []string{"h3"}})
		if err != nil {
			cancel()
			t.Fatalf("h3 tls config: %v", err)
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case transportQuic:
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{NextProtos: []string{"h3"}})
		if err != nil {
			cancel()
			t.Fatalf("quic tls config: %v", err)
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	}

	ln := newListener(lopts...)
	lmd := metadata.New(map[string]any{
		"handshake_timeout": cfg.HandshakeTimeout,
		"udp_idle":          cfg.UDPIdleTimeout,
		"udp_block_private": false, // 测试环境允许本地连接
	})
	if err := ln.Init(lmd); err != nil {
		cancel()
		t.Fatalf("listener init %s: %v", scheme, err)
	}

	stop := startService(t, ln, h, cancel)
	return ep, stop
}

func startService(t *testing.T, ln listener.Listener, h handler.Handler, cancel context.CancelFunc) func() {
	t.Helper()
	svc := service.NewService(ln, h, testLogger())
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.Serve()
	}()

	return func() {
		cancel()
		_ = svc.Close()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Log("service shutdown timed out")
		}
	}
}
