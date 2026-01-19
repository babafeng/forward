package app

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"forward/internal/builder"
	"forward/internal/chain"
	"forward/internal/config"

	"forward/inner/endpoint"
	"forward/inner/logging"
	"forward/inner/route"
	"forward/internal/handler"
	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/router"
	"forward/internal/service"
	"path/filepath"

	cini "forward/internal/config/ini"
	cjson "forward/internal/config/json"
	ctls "forward/internal/config/tls"

	_ "forward/internal/connector/http"
	_ "forward/internal/connector/socks5"
	_ "forward/internal/dialer/tcp"
	_ "forward/internal/dialer/tls"
	_ "forward/internal/handler/http"
	_ "forward/internal/handler/socks5"
	_ "forward/internal/listener/tcp"
)

func Main() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := parseArgs(os.Args[1:])
	logger := cfg.Logger
	if logger == nil {
		logger = logging.New(logging.Options{Level: logging.LevelError})
	}

	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		logger.Error("Parse args error: %v", err)
		return 2
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
	if !isProxyServer(cfg.Listen.Scheme) {
		return fmt.Errorf("unsupported listen scheme: %s", cfg.Listen.Scheme)
	}
	return runProxyServer(ctx, cfg)
}

func runProxyServer(ctx context.Context, cfg config.Config) error {
	cfg.Mode = config.ModeProxyServer

	if !cfg.Listen.HasUserPass() {
		cfg.Logger.Warn("Proxy server listening on %s without authentication", cfg.Listen.Address())
	}

	rt, err := buildRouter(cfg)
	if err != nil {
		return err
	}

	handlerScheme := strings.ToLower(cfg.Listen.Scheme)
	if handlerScheme == "https" {
		handlerScheme = "http"
	}
	if handlerScheme == "socks5h" {
		handlerScheme = "socks5"
	}

	newHandler := registry.HandlerRegistry().Get(handlerScheme)
	if newHandler == nil {
		return fmt.Errorf("handler not registered for scheme %s", handlerScheme)
	}

	h := newHandler(
		handler.RouterOption(rt),
		handler.AuthOption(cfg.Listen.User),
		handler.LoggerOption(cfg.Logger),
	)

	md := metadata.New(map[string]any{
		"transparent":       strings.EqualFold(cfg.Listen.Query.Get("transparent"), "true"),
		"insecure":          cfg.Insecure,
		"handshake_timeout": cfg.HandshakeTimeout,
		"udp_idle":          cfg.UDPIdleTimeout,
		"max_udp_sessions":  cfg.MaxUDPSessions,
	})
	if err := h.Init(md); err != nil {
		return err
	}

	newListener := registry.ListenerRegistry().Get(strings.ToLower(cfg.Listen.Scheme))
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
	}
	if strings.EqualFold(cfg.Listen.Scheme, "https") {
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{
			NextProtos: []string{"h2", "http/1.1"},
		})
		if err != nil {
			return err
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	}

	ln := newListener(lopts...)
	if err := ln.Init(nil); err != nil {
		return err
	}

	svc := service.NewService(ln, h)
	go func() {
		<-ctx.Done()
		_ = svc.Close()
	}()

	cfg.Logger.Info("Forward internal %s proxy listening on %s", cfg.Listen.Scheme, cfg.Listen.Address())
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
		defaultRoute = chain.NewRoute()
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
	configFile := fs.String("C", "", "Path to JSON config file")
	routeFile := fs.String("R", "", "Path to proxy route config file")
	insecure := fs.Bool("insecure", false, "Disable TLS certificate verification")
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
		return cfg, nil
	}

	if *configFile != "" {
		return parseConfigFile(*configFile)
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

	if len(listenFlags) == 0 {
		defaultPath, err := cjson.FindDefaultConfig()
		if err != nil {
			fs.Usage()
			return cfg, err
		}
		return parseConfigFile(defaultPath)
	}

	for _, l := range listenFlags {
		ep, err := endpoint.Parse(l)
		if err != nil {
			return cfg, fmt.Errorf("parse -L %s: %w", l, err)
		}
		cfg.Listeners = append(cfg.Listeners, ep)
	}
	cfg.Listen = cfg.Listeners[0]

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
	switch strings.ToLower(scheme) {
	case "http", "https", "socks5", "socks5h":
		return true
	default:
		return false
	}
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
