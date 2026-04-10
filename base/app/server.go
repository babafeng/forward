package app

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"forward/base/endpoint"
	"forward/base/logging"
	"forward/internal/builder"
	"forward/internal/chain"
	"forward/internal/config"
	"forward/internal/handler"
	hy2server "forward/internal/hysteria2"
	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
	rev "forward/internal/reverse"
	revclient "forward/internal/reverse/client"
	"forward/internal/router"
	"forward/internal/service"

	ctls "forward/internal/config/tls"

	revhandler "forward/internal/handler/reverse"
	quiclistener "forward/internal/listener/quic"
)

func runProxyServer(ctx context.Context, cfg config.Config, routers *routerCache) error {
	cfg.Mode = config.ModeProxyServer

	if !cfg.Listen.HasUserPass() && !strings.EqualFold(cfg.Listen.Scheme, "tproxy") {
		cfg.Logger.Warn("Proxy server listening on %s without authentication", cfg.Listen.Address())
	}

	rt, err := routers.getOrBuild(cfg)
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
	if tlsOpt, err := buildTLSOption(cfg, handlerScheme, listenerScheme, transport); err != nil {
		return err
	} else if tlsOpt != nil {
		lopts = append(lopts, tlsOpt)
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
		"max_idle_conns": readPositiveQueryInt(
			cfg.Listen.Query,
			config.DefaultHTTPMaxIdleConns,
			"max_idle_conns",
			"max-idle-conns",
		),
		"max_idle_conns_per_host": readPositiveQueryInt(
			cfg.Listen.Query,
			config.DefaultHTTPMaxIdleConnsPerHost,
			"max_idle_conns_per_host",
			"max-idle-conns-per-host",
		),
		"max_conns_per_host": readPositiveQueryInt(
			cfg.Listen.Query,
			config.DefaultHTTPMaxConnsPerHost,
			"max_conns_per_host",
			"max-conns-per-host",
		),
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

	if handlerScheme == "vless" && listenerScheme == "reality" {
		passValidatorToHandler(ln, h)
	}

	svc := service.NewService(ln, h, cfg.Logger, cfg.DebugVerbose)
	go func() {
		<-ctx.Done()
		_ = svc.Close()
	}()

	cfg.Logger.Info("forward %s proxy listening on %s", cfg.Listen.Scheme, cfg.Listen.Address())
	return svc.Serve()
}

func runHysteria2ProxyServer(ctx context.Context, cfg config.Config, rt router.Router) error {
	return hy2server.Serve(ctx, cfg, rt)
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

	svc := service.NewService(ln, h, cfg.Logger, cfg.DebugVerbose)
	go func() {
		<-ctx.Done()
		_ = svc.Close()
	}()

	cfg.Logger.Info("forward reverse server listening on %s (%s)", cfg.Listen.Address(), cfg.Listen.Scheme)
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

	passValidatorToHandler(ln, vlessHandler)

	svc := service.NewService(ln, vlessHandler, cfg.Logger, cfg.DebugVerbose)
	go func() {
		<-ctx.Done()
		_ = svc.Close()
	}()

	cfg.Logger.Info("forward reverse server listening on %s (%s)", cfg.Listen.Address(), cfg.Listen.Scheme)
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

func runPortForward(ctx context.Context, cfg config.Config, routers *routerCache) error {
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

	rt, err := routers.getOrBuild(routeCfg)
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
	if tlsOpt, err := buildTLSOption(cfg, baseScheme, listenerScheme, transport); err != nil {
		return err
	} else if tlsOpt != nil {
		lopts = append(lopts, tlsOpt)
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

	svc := service.NewService(ln, h, cfg.Logger, cfg.DebugVerbose)
	go func() {
		<-ctx.Done()
		_ = svc.Close()
	}()

	cfg.Logger.Info("forward %s forward listening on %s -> %s", cfg.Listen.Scheme, cfg.Listen.Address(), target)
	return svc.Serve()
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

func readPositiveQueryInt(q url.Values, fallback int, keys ...string) int {
	for _, key := range keys {
		raw := strings.TrimSpace(q.Get(key))
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			continue
		}
		return n
	}
	return fallback
}
