package app

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"forward/internal/config"
	"forward/internal/endpoint"
	"forward/internal/logging"
	"forward/internal/route"

	cini "forward/internal/config/ini"
	cjson "forward/internal/config/json"

	rc "forward/internal/reverse/client"

	xlog "github.com/xtls/xray-core/common/log"
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

	xlog.RegisterHandler(&xrayLogHandler{level: cfg.LogLevel.String(), logger: logger})
	if cfg.Route != nil && cfg.RouteStore == nil {
		store, err := route.NewStore(cfg.Route, logger)
		if err != nil {
			logger.Error("Route init error: %v", err)
			return 2
		}
		cfg.RouteStore = store
	}

	if cfg.RouteStore != nil && cfg.RoutePath != "" {
		go func() {
			var lastMod time.Time
			var lastSize int64
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					info, err := os.Stat(cfg.RoutePath)
					if err != nil {
						logger.Error("Route reload failed: %v", err)
						continue
					}
					if info.ModTime().Equal(lastMod) && info.Size() == lastSize {
						continue
					}
					lastMod = info.ModTime()
					lastSize = info.Size()
					start := time.Now()
					newCfg, err := parseRouteConfig(cfg.RoutePath)
					if err != nil {
						logger.Error("Route reload failed: %v", err)
						continue
					}
					if !sameListeners(cfg.Listeners, newCfg.Listeners) {
						logger.Warn("Route reload ignored listen changes from %s", cfg.RoutePath)
					}
					if err := cfg.RouteStore.Update(newCfg.Route, logger); err != nil {
						logger.Error("Route reload failed: %v", err)
						continue
					}
					cfg.Route = newCfg.Route
					logger.Info("Route reloaded from %s in %s", cfg.RoutePath, time.Since(start))
				}
			}
		}()
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
	if isReverseForwardServer(cfg) {
		return runReverseServer(ctx, cfg)
	}

	if isReverseForwardClient(cfg) {
		return runReverseClient(ctx, cfg)
	}

	if isPortForward(cfg) {
		return runPortForward(ctx, cfg)
	}

	if isProxyServer(cfg) {
		return runProxyServer(ctx, cfg)
	}

	return fmt.Errorf("unknown mode or scheme: %s", cfg.Listen.Scheme)
}

func runReverseClient(ctx context.Context, cfg config.Config) error {
	cfg.Mode = config.ModeReverseClient
	client, err := rc.New(cfg)
	if err != nil {
		return fmt.Errorf("reverse client init error: %w", err)
	}
	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		return fmt.Errorf("reverse client run error: %w", err)
	}
	return nil
}

func runPortForward(ctx context.Context, cfg config.Config) error {
	cfg.Mode = config.ModePortForward

	if cfg.Listen.FAddress != "" {
		ef, _ := endpoint.Parse(fmt.Sprintf("%s://%s", cfg.Listen.Scheme, cfg.Listen.FAddress))
		cfg.Forward = &ef
	} else {
		if cfg.Forward == nil {
			return fmt.Errorf("missing target address (use -L .../target or -F target)")
		}
	}

	_, err := runForwarders(ctx, cfg)
	return err
}

func runProxyServer(ctx context.Context, cfg config.Config) error {
	cfg.Mode = config.ModeProxyServer

	if !cfg.Listen.HasUserPass() {
		cfg.Logger.Warn("Proxy server listening on %s without authentication", cfg.Listen.Address())
	}

	_, err := runForwarders(ctx, cfg)
	return err
}

func runReverseServer(ctx context.Context, cfg config.Config) error {
	cfg.Mode = config.ModeReverseServer

	if !cfg.Listen.HasUserPass() {
		cfg.Logger.Warn("Reverse server listening on %s without authentication", cfg.Listen.Address())
	}

	_, err := runForwarders(ctx, cfg)
	return err
}

func runForwarders(ctx context.Context, cfg config.Config) (int, error) {
	fwd, err := NewForwarder(cfg)
	if err != nil {
		return 2, err
	}

	if err := fwd.Run(ctx); err != nil && ctx.Err() == nil {
		return 1, err
	}
	return 0, nil
}

func parseArgs(args []string) (config.Config, error) {
	fs := flag.NewFlagSet("forward", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var listenFlags stringSlice
	fs.Var(&listenFlags, "L", "Local listen endpoint, e.g. https://127.0.0.1:443 (can be repeated)")
	var forwardFlags stringSlice
	fs.Var(&forwardFlags, "F", "Forward target endpoint, e.g. https://remote.com:443 (can be repeated)")
	configFile := fs.String("C", "", "Path to JSON config file")
	routeFile := fs.String("R", "", "Path to proxy route config file")
	insecure := fs.Bool("insecure", false, "Disable TLS certificate verification")
	isDebug := fs.Bool("debug", false, "Enable debug logging")
	isVersion := fs.Bool("version", false, "Show version information")

	println("Forward", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
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
		cfg, err := cini.ParseFile(path)
		if err != nil {
			return config.Config{}, err
		}
		cfg.RoutePath = path
		return cfg, nil
	default:
		return config.Config{}, fmt.Errorf("route config must be .ini/.conf/.cfg")
	}
}

func isProxyServer(cfg config.Config) bool {
	switch strings.ToLower(cfg.Listen.Scheme) {
	case "http", "https", "http3", "socks5", "tls", "quic", "socks5h", "vless", "vless+reality", "reality":
		return true
	default:
		return false
	}
}

func isPortForward(cfg config.Config) bool {
	// Supports:
	//   -L tcp://:2222 -F tcp://10.0.0.10:22
	//   -L udp://:5353 -F udp://8.8.8.8:53
	//   -L tcp://:2222/10.0.0.10:22
	//   -L udp://:5353/8.8.8.8:53

	ls := strings.ToLower(cfg.Listen.Scheme)
	if ls != "tcp" && ls != "udp" {
		return false
	}

	if cfg.Forward == nil {
		return cfg.Listen.RAddress != "" && cfg.Listen.FAddress != ""
	}

	return strings.EqualFold(cfg.Listen.Scheme, cfg.Forward.Scheme)
}

func isReverseForwardServer(cfg config.Config) bool {
	// remote server: -L tls://user:pass@0.0.0.0:443?bind=true or -L tls://user:pass@:443?bind=true
	// remote server: -L reality://uuid@:2333?bind=true
	switch strings.ToLower(cfg.Listen.Scheme) {
	case "tls", "http3", "https", "quic", "vless+reality", "reality":
		return cfg.Listen.Query.Get("bind") == "true"
	default:
		return false
	}
}

func isReverseForwardClient(cfg config.Config) bool {
	// internal server tcp: -L tcp://127.0.0.1:2222/10.0.0.10:22 -F tls://user:pass@remote.com:443
	// internal server udp: -L udp://127.0.0.1:5353/10.0.0.10:53 -F tls://user:pass@remote.com:443
	// remote server will listen 127.0.0.1:2222

	// internal server tcp: -L tcp://0.0.0.0:2222/10.0.0.10:22 -F tls://user:pass@remote.com:443
	// internal server tcp: -L tcp://:2222/10.0.0.10:22 -F tls://user:pass@remote.com:443
	// internal server udp: -L udp://0.0.0.0:5353/10.0.0.10:53 -F tls://user:pass@remote.com:443
	// internal server udp: -L udp://:5353/10.0.0.10:53 -F tls://user:pass@remote.com:443
	// remote server will listen 0.0.0.0:2222

	if cfg.Forward == nil {
		return false
	}

	if cfg.Forward.Scheme == "" || cfg.Listen.RAddress == "" || cfg.Listen.FAddress == "" {
		return false
	}

	ls := strings.ToLower(cfg.Listen.Scheme)
	return ls == "tcp" || ls == "udp"
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

func sameListeners(a, b []endpoint.Endpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].String() != b[i].String() {
			return false
		}
	}
	return true
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
			h.logger.Debug(txt)
		}
	case xlog.Severity_Info:
		h.logger.Info(txt)
	case xlog.Severity_Warning:
		h.logger.Warn(txt)
	case xlog.Severity_Error:
		h.logger.Error(txt)
	default:
		h.logger.Info(txt)
	}
}
