package app

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"forward/internal/builder"
	"forward/internal/chain"
	"forward/internal/config"

	"forward/base/endpoint"
	"forward/base/logging"
	"forward/base/route"
	"forward/internal/handler"
	hy2server "forward/internal/hysteria2"
	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
	rev "forward/internal/reverse"
	revclient "forward/internal/reverse/client"
	"forward/internal/router"
	"forward/internal/service"
	"path/filepath"

	cini "forward/internal/config/ini"
	cjson "forward/internal/config/json"
	ctls "forward/internal/config/tls"

	xlog "github.com/xtls/xray-core/common/log"

	_ "forward/internal/connector/http"
	_ "forward/internal/connector/http2"
	_ "forward/internal/connector/http3"
	_ "forward/internal/connector/hysteria2"
	_ "forward/internal/connector/socks5"
	_ "forward/internal/connector/tcp"
	_ "forward/internal/dialer/dtls"
	_ "forward/internal/dialer/h2"
	_ "forward/internal/dialer/h3"
	_ "forward/internal/dialer/http3"
	_ "forward/internal/dialer/hysteria2"
	_ "forward/internal/dialer/quic"
	_ "forward/internal/dialer/tcp"
	_ "forward/internal/dialer/tls"
	_ "forward/internal/dialer/udp"
	_ "forward/internal/dialer/ws"
	_ "forward/internal/handler/http"
	revhandler "forward/internal/handler/reverse"
	_ "forward/internal/handler/socks5"
	_ "forward/internal/handler/tcp"
	_ "forward/internal/handler/tproxy"
	_ "forward/internal/handler/udp"
	_ "forward/internal/listener/dtls"
	_ "forward/internal/listener/h2"
	_ "forward/internal/listener/h3"
	_ "forward/internal/listener/http3"
	quiclistener "forward/internal/listener/quic"
	_ "forward/internal/listener/tcp"
	_ "forward/internal/listener/tproxy"
	_ "forward/internal/listener/udp"

	// VLESS + Reality
	_ "forward/internal/connector/vless"
	_ "forward/internal/dialer/reality"
	_ "forward/internal/handler/vless"
	_ "forward/internal/listener/reality"

	// VMess
	_ "forward/internal/connector/vmess"
	_ "forward/internal/handler/vmess"

	// Shadowsocks
	_ "forward/internal/connector/ss"
	_ "forward/internal/handler/ss"
)

const defaultWarmupURL = "http://www.gstatic.com/generate_204"

func Main() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := parseArgs(os.Args[1:])
	logger := cfg.Logger
	if logger == nil {
		logger = logging.New(logging.Options{Level: logging.LevelError})
	}
	xlog.RegisterHandler(&xrayLogHandler{level: cfg.LogLevel.String(), logger: logger})

	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		logger.Error("Parse args error: %v", err)
		return 2
	}
	if len(cfg.DNSParameters.Servers) > 0 {
		chain.SetDefaultResolver(cfg.DNSParameters.Servers)
	}

	for _, node := range cfg.Nodes {
		if node.Insecure {
			logger.Warn("Node %s: --insecure is enabled, TLS verification is disabled", node.Name)
		}
	}

	var wg sync.WaitGroup
	listenerCount := 0
	for _, node := range cfg.Nodes {
		listenerCount += len(node.Listeners)
	}
	errChan := make(chan error, listenerCount)

	for _, node := range cfg.Nodes {
		for _, l := range node.Listeners {
			wg.Add(1)
			subCfg := buildNodeConfig(cfg, node, l)
			go func(c config.Config) {
				defer wg.Done()
				if err := runOne(ctx, c); err != nil {
					logger.Error("[%s] Error running listener %s: %v", c.NodeName, c.Listen.RedactedString(), err)
					errChan <- err
					stop()
				}
			}(subCfg)
		}
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return 1
	}
	return 0
}

func buildNodeConfig(global config.Config, node config.NodeConfig, listen endpoint.Endpoint) config.Config {
	cfg := global
	cfg.NodeName = node.Name
	cfg.Listen = listen
	cfg.Listeners = node.Listeners
	cfg.Forward = node.Forward
	cfg.ForwardChain = node.ForwardChain
	cfg.Insecure = node.Insecure
	return cfg
}

func runOne(ctx context.Context, cfg config.Config) error {
	if isReverseServer(cfg) {
		return runReverseServer(ctx, cfg)
	}
	if isReverseClient(cfg) {
		return runReverseClient(ctx, cfg)
	}
	if isPortForward(cfg) {
		return runPortForward(ctx, cfg)
	}
	if !isProxyServer(cfg.Listen.Scheme) {
		return fmt.Errorf("unsupported listen scheme: %s", cfg.Listen.Scheme)
	}
	return runProxyServer(ctx, cfg)
}

func runProxyServer(ctx context.Context, cfg config.Config) error {
	cfg.Mode = config.ModeProxyServer

	if !cfg.Listen.HasUserPass() && !strings.EqualFold(cfg.Listen.Scheme, "tproxy") {
		cfg.Logger.Warn("Proxy server listening on %s without authentication", cfg.Listen.Address())
	}

	rt, err := buildRouter(cfg)
	if err != nil {
		return err
	}

	rawScheme := strings.ToLower(cfg.Listen.Scheme)
	if rawScheme == "hysteria2" || rawScheme == "hy2" {
		return runHysteria2ProxyServer(ctx, cfg, rt)
	}

	handlerScheme, listenerScheme, transport := normalizeProxySchemes(rawScheme)

	// 先创建并初始化 Listener
	newListener := registry.ListenerRegistry().Get(listenerScheme)
	if newListener == nil {
		newListener = registry.ListenerRegistry().Get("tcp")
	}
	if newListener == nil {
		return fmt.Errorf("listener not registered for scheme %s", cfg.Listen.Scheme)
	}

	lopts := []listener.Option{
		listener.AddrOption(cfg.Listen.Address()),
		listener.LoggerOption(cfg.Logger),
		listener.RouterOption(rt),
		listener.ContextOption(ctx),
	}
	switch {
	case listenerScheme == "http3":
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{
			NextProtos: []string{"h3"},
		})
		if err != nil {
			return err
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case listenerScheme == "h3":
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{
			NextProtos: []string{"h3"},
		})
		if err != nil {
			return err
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case listenerScheme == "http2":
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{
			NextProtos: []string{"h2"},
		})
		if err != nil {
			return err
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case listenerScheme == "h2":
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{
			NextProtos: []string{"h2"},
		})
		if err != nil {
			return err
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case transport == transportTLS:
		tlsOpts := ctls.ServerOptions{}
		if handlerScheme == "http" {
			tlsOpts.NextProtos = []string{"h2", "http/1.1"}
		}
		tlsCfg, err := ctls.ServerConfig(cfg, tlsOpts)
		if err != nil {
			return err
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case transport == transportDTLS:
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{})
		if err != nil {
			return err
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	}

	ln := newListener(lopts...)
	// 构建 listener metadata
	lmdMap := map[string]any{
		"handshake_timeout": cfg.HandshakeTimeout,
		// Reality Listener 需要的配置
		metadata.KeyHost:    cfg.Listen.Host,
		metadata.KeyPort:    cfg.Listen.Port,
		metadata.KeySNI:     cfg.Listen.Query.Get("sni"),
		metadata.KeyShortID: cfg.Listen.Query.Get("sid"),
		metadata.KeyFlow:    cfg.Listen.Query.Get("flow"),
		metadata.KeyNetwork: cfg.Listen.Query.Get("type"),
		"dest":              cfg.Listen.Query.Get("dest"),
		"privatekey":        cfg.Listen.Query.Get("key"),
	}
	if listenerScheme == "tproxy" && cfg.TProxy != nil {
		if len(cfg.TProxy.Network) > 0 {
			lmdMap["network"] = strings.Join(cfg.TProxy.Network, ",")
		}
		lmdMap["udp_idle"] = cfg.UDPIdleTimeout
	}
	if cfg.Listen.User != nil {
		lmdMap[metadata.KeyUUID] = cfg.Listen.User.Username()
		if p, ok := cfg.Listen.User.Password(); ok {
			lmdMap["secret"] = p
		}
	}
	lmd := metadata.New(lmdMap)
	if err := ln.Init(lmd); err != nil {
		return err
	}

	// 创建 Handler
	newHandler := registry.HandlerRegistry().Get(handlerScheme)
	if newHandler == nil {
		return fmt.Errorf("handler not registered for scheme %s", handlerScheme)
	}

	h := newHandler(
		handler.RouterOption(rt),
		handler.AuthOption(cfg.Listen.User),
		handler.LoggerOption(cfg.Logger),
	)

	mdMap := map[string]any{
		"transparent":         strings.EqualFold(cfg.Listen.Query.Get("transparent"), "true"),
		"insecure":            cfg.Insecure,
		"handshake_timeout":   cfg.HandshakeTimeout,
		"udp_idle":            cfg.UDPIdleTimeout,
		"max_udp_sessions":    cfg.MaxUDPSessions,
		"read_header_timeout": cfg.ReadHeaderTimeout,
		"max_header_bytes":    cfg.MaxHeaderBytes,
		"idle_timeout":        cfg.IdleTimeout,
	}
	if handlerScheme == "tproxy" && cfg.TProxy != nil {
		mdMap["sniffing"] = cfg.TProxy.Sniffing
		if len(cfg.TProxy.DestOverride) > 0 {
			mdMap["dest_override"] = strings.Join(cfg.TProxy.DestOverride, ",")
		}
		mdMap["sniff_timeout"] = cfg.ReadHeaderTimeout
	}
	md := metadata.New(mdMap)

	// VMess Handler 需要额外的配置
	if handlerScheme == "vmess" {
		uuid := ""
		security := ""
		if cfg.Listen.User != nil {
			security = cfg.Listen.User.Username() // 加密方式在用户名
			if p, ok := cfg.Listen.User.Password(); ok {
				uuid = p // UUID 在密码
			}
		}
		md.Set(metadata.KeyUUID, uuid)
		md.Set(metadata.KeySecurity, security)
		md.Set(metadata.KeyAlterID, cfg.Listen.Query.Get("alterId"))
	}

	// SS Handler 需要额外的配置
	if handlerScheme == "ss" {
		method := ""
		password := ""
		if cfg.Listen.User != nil {
			method = cfg.Listen.User.Username() // 加密方法在用户名
			if p, ok := cfg.Listen.User.Password(); ok {
				password = p // 密码在密码字段
			}
		}
		md.Set(metadata.KeyMethod, method)
		md.Set(metadata.KeyPassword, password)
	}

	if err := h.Init(md); err != nil {
		return err
	}

	if shouldWarmup(cfg) {
		startWarmup(ctx, cfg, h)
	}

	// 如果是 VLESS+Reality，传递 validator 给 Handler
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

	svc := service.NewService(ln, h, cfg.Logger)
	go func() {
		<-ctx.Done()
		_ = svc.Close()
	}()

	cfg.Logger.Info("Forward internal %s proxy listening on %s", cfg.Listen.Scheme, cfg.Listen.Address())
	return svc.Serve()
}

func runHysteria2ProxyServer(ctx context.Context, cfg config.Config, rt router.Router) error {
	return hy2server.Serve(ctx, cfg, rt)
}

func shouldWarmup(cfg config.Config) bool {
	if strings.TrimSpace(cfg.WarmupURL) == "" {
		return false
	}
	return len(cfg.ForwardChain) > 0 || cfg.Forward != nil
}

type warmupCapable interface {
	Warmup(context.Context, string) (int, error)
}

func startWarmup(ctx context.Context, cfg config.Config, h handler.Handler) {
	warmupURL := strings.TrimSpace(cfg.WarmupURL)
	if warmupURL == "" || h == nil {
		return
	}

	wu, ok := h.(warmupCapable)
	if !ok {
		cfg.Logger.Warn("Warmup skipped: handler does not support warmup")
		return
	}

	go func() {
		start := time.Now()
		wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		code, err := wu.Warmup(wctx, warmupURL)
		if err != nil {
			cfg.Logger.Warn("Warmup failed: %v", err)
			return
		}
		cfg.Logger.Info("Warmup success: %s (%d) in %s", warmupURL, code, time.Since(start))
	}()
}

func runReverseServer(ctx context.Context, cfg config.Config) error {
	cfg.Mode = config.ModeReverseServer

	if cfg.Listen.Query.Get("bind") != "true" {
		return fmt.Errorf("reverse server requires bind=true")
	}
	if !cfg.Listen.HasUserPass() {
		return fmt.Errorf("reverse server with bind=true requires authentication (user/pass)")
	}

	h := revhandler.NewHandler(
		handler.AuthOption(cfg.Listen.User),
		handler.LoggerOption(cfg.Logger),
	)
	hmd := metadata.New(map[string]any{
		"handshake_timeout": cfg.HandshakeTimeout,
		"udp_idle":          cfg.UDPIdleTimeout,
		"max_udp_sessions":  cfg.MaxUDPSessions,
	})
	if err := h.Init(hmd); err != nil {
		return err
	}

	scheme := strings.ToLower(cfg.Listen.Scheme)
	if scheme == "reality" || scheme == "vless+reality" {
		return runReverseRealityServer(ctx, cfg, h)
	}
	lopts := []listener.Option{
		listener.AddrOption(cfg.Listen.Address()),
		listener.LoggerOption(cfg.Logger),
	}
	if protos := rev.NextProtosForScheme(scheme); len(protos) > 0 {
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{NextProtos: protos})
		if err != nil {
			return err
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	}

	var ln listener.Listener
	if scheme == "http3" || scheme == "quic" {
		ln = quiclistener.NewListener(lopts...)
	} else {
		newListener := registry.ListenerRegistry().Get("tcp")
		if newListener == nil {
			return fmt.Errorf("listener not registered for scheme tcp")
		}
		ln = newListener(lopts...)
	}

	lmd := metadata.New(map[string]any{
		"handshake_timeout": cfg.HandshakeTimeout,
	})
	if err := ln.Init(lmd); err != nil {
		return err
	}

	svc := service.NewService(ln, h, cfg.Logger)
	go func() {
		<-ctx.Done()
		_ = svc.Close()
	}()

	cfg.Logger.Info("Forward internal reverse server listening on %s (%s)", cfg.Listen.Address(), cfg.Listen.Scheme)
	return svc.Serve()
}

func runReverseRealityServer(ctx context.Context, cfg config.Config, revHandler handler.Handler) error {
	newHandler := registry.HandlerRegistry().Get("vless")
	if newHandler == nil {
		return fmt.Errorf("handler not registered for scheme vless")
	}

	pipeRouter := &reversePipeRouter{
		handler: revHandler,
		logger:  cfg.Logger,
	}

	vlessHandler := newHandler(
		handler.RouterOption(pipeRouter),
		handler.AuthOption(cfg.Listen.User),
		handler.LoggerOption(cfg.Logger),
	)
	if err := vlessHandler.Init(nil); err != nil {
		return err
	}

	newListener := registry.ListenerRegistry().Get("reality")
	if newListener == nil {
		return fmt.Errorf("listener not registered for scheme reality")
	}

	lopts := []listener.Option{
		listener.AddrOption(cfg.Listen.Address()),
		listener.LoggerOption(cfg.Logger),
	}
	ln := newListener(lopts...)

	lmdMap := map[string]any{
		metadata.KeyHost:        cfg.Listen.Host,
		metadata.KeyPort:        cfg.Listen.Port,
		metadata.KeySecurity:    cfg.Listen.Query.Get("security"),
		metadata.KeyNetwork:     cfg.Listen.Query.Get("type"),
		metadata.KeySNI:         cfg.Listen.Query.Get("sni"),
		metadata.KeyFingerprint: cfg.Listen.Query.Get("fp"),
		metadata.KeyPublicKey:   cfg.Listen.Query.Get("pbk"),
		metadata.KeyShortID:     cfg.Listen.Query.Get("sid"),
		metadata.KeySpiderX:     cfg.Listen.Query.Get("spiderx"),
		metadata.KeyALPN:        cfg.Listen.Query.Get("alpn"),
		metadata.KeyInsecure:    cfg.Insecure,
		metadata.KeyFlow:        cfg.Listen.Query.Get("flow"),
		"dest":                  cfg.Listen.Query.Get("dest"),
		"privatekey":            cfg.Listen.Query.Get("key"),
	}
	if cfg.Listen.User != nil {
		lmdMap[metadata.KeyUUID] = cfg.Listen.User.Username()
	}
	lmd := metadata.New(lmdMap)
	if err := ln.Init(lmd); err != nil {
		return err
	}

	type validatorProvider interface {
		Validator() interface{}
	}
	type validatorSetter interface {
		SetValidator(v interface{})
	}
	if vp, ok := ln.(validatorProvider); ok {
		if vs, ok := vlessHandler.(validatorSetter); ok {
			vs.SetValidator(vp.Validator())
		}
	}

	svc := service.NewService(ln, vlessHandler, cfg.Logger)
	go func() {
		<-ctx.Done()
		_ = svc.Close()
	}()

	cfg.Logger.Info("Forward internal reverse server listening on %s (%s)", cfg.Listen.Address(), cfg.Listen.Scheme)
	return svc.Serve()
}

func runReverseClient(ctx context.Context, cfg config.Config) error {
	cfg.Mode = config.ModeReverseClient

	if cfg.Listen.FAddress == "" {
		return fmt.Errorf("reverse client requires target address in listen path")
	}

	var hops []endpoint.Endpoint
	if len(cfg.ForwardChain) > 0 {
		hops = cfg.ForwardChain
	} else if cfg.Forward != nil {
		hops = []endpoint.Endpoint{*cfg.Forward}
	}
	if len(hops) == 0 {
		return fmt.Errorf("reverse client requires forward target")
	}

	route, err := builder.BuildReverseRoute(cfg, hops)
	if err != nil {
		return err
	}
	forward := hops[len(hops)-1]

	client := revclient.New(cfg, route, forward)
	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		return fmt.Errorf("reverse client run error: %w", err)
	}
	return nil
}

type reversePipeRouter struct {
	handler handler.Handler
	logger  *logging.Logger
}

func (r *reversePipeRouter) Route(ctx context.Context, _ string, _ string) (chain.Route, error) {
	return reversePipeRoute{handler: r.handler, logger: r.logger}, nil
}

type reversePipeRoute struct {
	handler handler.Handler
	logger  *logging.Logger
}

func (r reversePipeRoute) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	client, server := net.Pipe()
	go func() {
		if err := r.handler.Handle(ctx, server); err != nil && r.logger != nil {
			r.logger.Debug("Reverse server pipe handler error: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = client.Close()
		_ = server.Close()
	}()
	return client, nil
}

func (r reversePipeRoute) Nodes() []*chain.Node {
	return nil
}

func runPortForward(ctx context.Context, cfg config.Config) error {
	cfg.Mode = config.ModePortForward

	baseScheme, transport := splitSchemeTransport(cfg.Listen.Scheme)
	if baseScheme == "udp" && transport != transportNone {
		return fmt.Errorf("udp over %s is not supported", transport)
	}

	target, useForwardAsTarget, err := resolveForwardTarget(cfg)
	if err != nil {
		return err
	}

	routeCfg := cfg
	if useForwardAsTarget {
		routeCfg.Forward = nil
		routeCfg.ForwardChain = nil
	}

	rt, err := buildRouter(routeCfg)
	if err != nil {
		return err
	}

	newHandler := registry.HandlerRegistry().Get(baseScheme)
	if newHandler == nil {
		return fmt.Errorf("handler not registered for scheme %s", baseScheme)
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
		return err
	}

	listenerScheme := baseScheme
	if transport == transportDTLS {
		listenerScheme = "dtls"
	}
	if transport == transportH2 {
		listenerScheme = "h2"
	}
	if transport == transportH3 {
		listenerScheme = "h3"
	}
	newListener := registry.ListenerRegistry().Get(listenerScheme)
	if newListener == nil {
		return fmt.Errorf("listener not registered for scheme %s", listenerScheme)
	}
	lopts := []listener.Option{
		listener.AddrOption(cfg.Listen.Address()),
		listener.LoggerOption(cfg.Logger),
		listener.RouterOption(rt),
	}
	switch transport {
	case transportTLS, transportDTLS:
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{})
		if err != nil {
			return err
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case transportH2:
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{
			NextProtos: []string{"h2"},
		})
		if err != nil {
			return err
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	case transportH3:
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{
			NextProtos: []string{"h3"},
		})
		if err != nil {
			return err
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	}
	ln := newListener(lopts...)

	lmdMap := map[string]any{
		"handshake_timeout": cfg.HandshakeTimeout,
		"udp_idle":          cfg.UDPIdleTimeout,
	}
	if cfg.Listen.User != nil {
		if p, ok := cfg.Listen.User.Password(); ok {
			lmdMap["secret"] = p
		}
	}
	lmd := metadata.New(lmdMap)
	if err := ln.Init(lmd); err != nil {
		return err
	}

	svc := service.NewService(ln, h, cfg.Logger)
	go func() {
		<-ctx.Done()
		_ = svc.Close()
	}()

	cfg.Logger.Info("Forward internal %s forward listening on %s -> %s", cfg.Listen.Scheme, cfg.Listen.Address(), target)
	return svc.Serve()
}

func buildRouter(cfg config.Config) (router.Router, error) {
	var hops []endpoint.Endpoint
	if len(cfg.ForwardChain) > 0 {
		hops = cfg.ForwardChain
	} else if cfg.Forward != nil {
		hops = []endpoint.Endpoint{*cfg.Forward}
	}

	var defaultRoute chain.Route
	if len(hops) > 0 {
		rt, err := builder.BuildRoute(cfg, hops)
		if err != nil {
			return nil, err
		}
		defaultRoute = rt
	} else {
		defaultRoute = chain.NewRouteWithTimeout(cfg.DialTimeout)
	}

	if cfg.Route == nil {
		return router.NewStatic(defaultRoute), nil
	}

	store := cfg.RouteStore
	if store == nil {
		rstore, err := route.NewStore(cfg.Route, cfg.Logger)
		if err != nil {
			return nil, err
		}
		store = rstore
	}

	proxies := map[string]chain.Route{}
	for name, ep := range cfg.Route.Proxies {
		rt, err := builder.BuildRoute(cfg, []endpoint.Endpoint{ep})
		if err != nil {
			return nil, err
		}
		for _, node := range rt.Nodes() {
			if node != nil {
				node.Display = name
			}
		}
		proxies[route.NormalizeProxyName(name)] = rt
	}

	return router.NewStore(store, defaultRoute, proxies), nil
}

func parseArgs(args []string) (config.Config, error) {
	fs := flag.NewFlagSet("forward-internal", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var listenFlags stringSlice
	fs.Var(&listenFlags, "L", "Local listen endpoint, e.g. http://127.0.0.1:8080 (can be repeated)")
	var forwardFlags stringSlice
	fs.Var(&forwardFlags, "F", "Forward target endpoint, e.g. socks5://remote:1080 (can be repeated)")
	tproxyPort := fs.Int("T", 0, "Enable transparent proxy listener on 127.0.0.1:<port> (use with -F only)")
	configFile := fs.String("C", "", "Path to JSON config file")
	routeFile := fs.String("R", "", "Path to proxy route config file")
	insecure := fs.Bool("insecure", false, "Disable TLS certificate verification")
	warmup := fs.Bool("warmup", false, "Warm up forward chain once at startup")
	warmupURL := fs.String("warmup-url", defaultWarmupURL, "Warmup request URL (used with --warmup)")
	isDebug := fs.Bool("debug", false, "Enable debug logging")
	isVersion := fs.Bool("version", false, "Show version information")

	fmt.Printf("Forward internal %s %s %s %s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if *isVersion {
		return config.Config{}, nil
	}

	fs.Usage = func() { Usage(fs) }

	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}

	if tproxyPort != nil && *tproxyPort > 0 {
		if *configFile != "" || *routeFile != "" || len(listenFlags) > 0 {
			return config.Config{}, fmt.Errorf("-T cannot be used with -C/-R/-L")
		}
		if len(forwardFlags) == 0 {
			return config.Config{}, fmt.Errorf("-T requires -F (one or more forward endpoints)")
		}
	}

	if *routeFile != "" {
		if *configFile != "" || len(listenFlags) > 0 || len(forwardFlags) > 0 {
			return config.Config{}, fmt.Errorf("-R cannot be used with -C/-L/-F")
		}
		cfg, err := parseRouteConfig(*routeFile)
		if err != nil {
			return config.Config{}, err
		}
		if isDebug != nil && *isDebug {
			cfg.Logger = logging.New(logging.Options{Level: logging.LevelDebug})
			cfg.LogLevel = logging.LevelDebug
		}
		if warmup != nil && *warmup {
			cfg.WarmupURL = strings.TrimSpace(*warmupURL)
			if cfg.WarmupURL == "" {
				return config.Config{}, fmt.Errorf("--warmup-url cannot be empty")
			}
		}
		return cfg, nil
	}

	if *configFile != "" {
		cfg, err := parseConfigFile(*configFile)
		if err != nil {
			return config.Config{}, err
		}
		if warmup != nil && *warmup {
			cfg.WarmupURL = strings.TrimSpace(*warmupURL)
			if cfg.WarmupURL == "" {
				return config.Config{}, fmt.Errorf("--warmup-url cannot be empty")
			}
		}
		return cfg, nil
	}

	logLevel := "info"
	if isDebug != nil && *isDebug {
		logLevel = "debug"
	}

	cfg := config.Config{}

	llevel, err := logging.ParseLevel(logLevel)
	if err != nil {
		return config.Config{}, err
	}
	logger := logging.New(logging.Options{Level: llevel})
	cfg.Logger = logger
	cfg.LogLevel = llevel

	if (tproxyPort == nil || *tproxyPort == 0) && len(listenFlags) == 0 {
		defaultPath, err := cjson.FindDefaultConfig()
		if err != nil {
			fs.Usage()
			return cfg, err
		}
		return parseConfigFile(defaultPath)
	}

	if tproxyPort != nil && *tproxyPort > 0 {
		addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(*tproxyPort))
		ep, err := endpoint.Parse("tproxy://" + addr)
		if err != nil {
			return cfg, fmt.Errorf("parse -T %d: %w", *tproxyPort, err)
		}
		cfg.Listeners = append(cfg.Listeners, ep)
		cfg.Listen = ep
		cfg.TProxy = &config.TProxyConfig{
			Port:         *tproxyPort,
			Network:      []string{"tcp"},
			Sniffing:     true,
			DestOverride: []string{"http", "tls", "quic"},
		}
	} else {
		for _, l := range listenFlags {
			ep, err := endpoint.Parse(l)
			if err != nil {
				return cfg, fmt.Errorf("parse -L %s: %w", l, err)
			}
			cfg.Listeners = append(cfg.Listeners, ep)
		}
		cfg.Listen = cfg.Listeners[0]
	}

	if len(forwardFlags) > 0 {
		for _, raw := range forwardFlags {
			ef, err := endpoint.Parse(raw)
			if err != nil {
				return cfg, fmt.Errorf("parse -F %s: %w", raw, err)
			}
			cfg.ForwardChain = append(cfg.ForwardChain, ef)
		}
		if len(cfg.ForwardChain) > 0 {
			last := cfg.ForwardChain[len(cfg.ForwardChain)-1]
			cfg.Forward = &last
		}
	}

	cfg.Insecure = *insecure
	if warmup != nil && *warmup {
		cfg.WarmupURL = strings.TrimSpace(*warmupURL)
		if cfg.WarmupURL == "" {
			return config.Config{}, fmt.Errorf("--warmup-url cannot be empty")
		}
	}

	cfg.Nodes = []config.NodeConfig{{
		Name:         "default",
		Listeners:    cfg.Listeners,
		Forward:      cfg.Forward,
		ForwardChain: cfg.ForwardChain,
		Insecure:     cfg.Insecure,
	}}

	config.ApplyDefaults(&cfg)
	return cfg, nil
}

func parseConfigFile(path string) (config.Config, error) {
	return cjson.ParseFile(path)
}

func parseRouteConfig(path string) (config.Config, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".ini", ".conf", ".cfg":
		return cini.ParseFile(path)
	default:
		return config.Config{}, fmt.Errorf("route config must be .ini/.conf/.cfg")
	}
}

func isProxyServer(scheme string) bool {
	base, transport := splitSchemeTransport(scheme)
	if base == "http2" || base == "http3" {
		return transport == transportNone
	}
	if base == "vless" {
		return true
	}
	if base == "vmess" {
		return true
	}
	if base == "hysteria2" || base == "hy2" {
		return true
	}
	if base == "ss" || base == "shadowsocks" {
		return true
	}
	switch base {
	case "http", "socks5", "socks5h", "tproxy":
		return true
	default:
		return false
	}
}

func isReverseServer(cfg config.Config) bool {
	if cfg.Listen.Query.Get("bind") != "true" {
		return false
	}
	switch strings.ToLower(cfg.Listen.Scheme) {
	case "tls", "https", "http3", "quic", "reality", "vless+reality":
		return true
	default:
		return false
	}
}

func isReverseClient(cfg config.Config) bool {
	ls := strings.ToLower(cfg.Listen.Scheme)
	if ls != "rtcp" && ls != "rudp" {
		return false
	}
	if cfg.Listen.FAddress == "" {
		return false
	}
	if cfg.Forward == nil && len(cfg.ForwardChain) == 0 {
		return false
	}
	return true
}

func isPortForward(cfg config.Config) bool {
	ls, transport := splitSchemeTransport(cfg.Listen.Scheme)
	if ls != "tcp" && ls != "udp" {
		return false
	}
	if ls == "udp" && transport != transportNone {
		return false
	}
	if cfg.Forward == nil {
		return cfg.Listen.FAddress != ""
	}
	fs, _ := splitSchemeTransport(cfg.Forward.Scheme)
	return strings.EqualFold(ls, fs)
}

func resolveForwardTarget(cfg config.Config) (target string, useForwardAsTarget bool, err error) {
	if cfg.Listen.FAddress != "" {
		return cfg.Listen.FAddress, false, nil
	}
	if cfg.Forward == nil {
		return "", false, fmt.Errorf("missing target address (use -L .../target or -F target)")
	}
	ls, _ := splitSchemeTransport(cfg.Listen.Scheme)
	fs, _ := splitSchemeTransport(cfg.Forward.Scheme)
	if !strings.EqualFold(ls, fs) {
		return "", false, fmt.Errorf("forward scheme %s does not match listen scheme %s", cfg.Forward.Scheme, cfg.Listen.Scheme)
	}
	if len(cfg.ForwardChain) > 1 {
		return "", false, fmt.Errorf("forward chain requires target in listen path")
	}
	return cfg.Forward.Address(), true, nil
}

type transportKind string

const (
	transportNone transportKind = ""
	transportTLS  transportKind = "tls"
	transportDTLS transportKind = "dtls"
	transportH2   transportKind = "h2"
	transportH3   transportKind = "h3"
)

func splitSchemeTransport(scheme string) (base string, transport transportKind) {
	s := strings.ToLower(strings.TrimSpace(scheme))
	switch s {
	case "https":
		return "http", transportTLS
	case "http2":
		return "http2", transportNone
	case "http3":
		return "http3", transportNone
	case "tls":
		return "http", transportTLS
	case "h2":
		return "http", transportH2
	case "h3":
		return "http", transportH3
	case "dtls":
		return "tcp", transportDTLS
	case "hysteria2", "hy2":
		return "hysteria2", transportNone
	// VLESS + Reality
	case "vless", "vless+reality", "reality":
		return "vless", transportNone
	case "vless+tls":
		return "vless", transportTLS
	// VMess
	case "vmess":
		return "vmess", transportNone
	case "vmess+tls":
		return "vmess", transportTLS
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
	// VLESS + Reality 带后缀
	if strings.HasSuffix(s, "+reality") {
		return strings.TrimSuffix(s, "+reality"), transportNone
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
	case "http2":
		handlerScheme = "http"
		listenerScheme = "http2"
		return handlerScheme, listenerScheme, transportNone
	case "socks5h":
		handlerScheme = "socks5"
	// VLESS + Reality
	case "vless":
		handlerScheme = "vless"
		listenerScheme = "reality"
		return handlerScheme, listenerScheme, transportNone
	// VMess
	case "vmess":
		handlerScheme = "vmess"
		listenerScheme = "tcp" // VMess 使用普通 TCP 监听
	// Shadowsocks
	case "ss", "shadowsocks":
		handlerScheme = "ss"
		listenerScheme = "tcp" // SS 使用普通 TCP 监听
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
	return
}

func Usage(fs *flag.FlagSet) {
	fmt.Fprintf(fs.Output(), "Usage of %s:\n", os.Args[0])
	fs.PrintDefaults()
}

type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type xrayLogHandler struct {
	level  string
	logger *logging.Logger
}

func (h *xrayLogHandler) Handle(msg xlog.Message) {
	var severity xlog.Severity
	var content interface{}

	if gm, ok := msg.(*xlog.GeneralMessage); ok {
		severity = gm.Severity
		content = gm.Content
	} else {
		severity = xlog.Severity_Info
		content = msg.String()
	}

	txt := fmt.Sprint(content)

	switch severity {
	case xlog.Severity_Debug:
		if h.level == "debug" {
			h.logger.Debug("%s", txt)
		}
	case xlog.Severity_Info:
		h.logger.Info("%s", txt)
	case xlog.Severity_Warning:
		h.logger.Warn("%s", txt)
	case xlog.Severity_Error:
		h.logger.Error("%s", txt)
	default:
		h.logger.Info("%s", txt)
	}
}
