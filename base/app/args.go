package app

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"forward/base/endpoint"
	"forward/base/logging"
	"forward/internal/config"

	cini "forward/internal/config/ini"
	cjson "forward/internal/config/json"
)

func parseArgs(args []string) (config.Config, subscribeOptions, error) {
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
	var subscribeURLs stringSlice
	fs.Var(&subscribeURLs, "S", "Subscribe URL to download and test nodes (Clash YAML format, can be repeated or comma-separated)")
	fs.Var(&subscribeURLs, "subscribe", "Subscribe URL to download and test nodes (Clash YAML format, can be repeated or comma-separated)")
	filterExpr := fs.String("filter", "", "Filter expression for node names (e.g. \"美国|US\", \"?!日本&?!JP\")")
	subUpdate := fs.Int("sub-update", 60, "Subscription auto-update interval in minutes (0 to disable)")
	connectURL := fs.String("connect-url", defaultConnectURL, "URL to test node latency (used with -S)")
	isDebug := fs.Bool("debug", false, "Enable debug logging")
	isDebugVerbose := fs.Bool("debug-verbose", false, "Enable verbose debug tracing (high-volume logs)")
	isVersion := fs.Bool("version", false, "Show version information")

	fmt.Printf("forward %s %s %s %s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if *isVersion {
		return config.Config{}, subscribeOptions{}, nil
	}

	fs.Usage = func() { Usage(fs) }

	if err := fs.Parse(args); err != nil {
		return config.Config{}, subscribeOptions{}, err
	}

	subOpts := subscribeOptions{
		URLs:       splitSubscribeValues(subscribeURLs),
		Filter:     strings.TrimSpace(*filterExpr),
		ConnectURL: strings.TrimSpace(*connectURL),
		Update:     *subUpdate,
	}

	if tproxyPort != nil && *tproxyPort > 0 {
		if *configFile != "" || *routeFile != "" || len(listenFlags) > 0 {
			return config.Config{}, subOpts, fmt.Errorf("-T cannot be used with -C/-R/-L")
		}
		if len(forwardFlags) == 0 {
			return config.Config{}, subOpts, fmt.Errorf("-T requires -F (one or more forward endpoints)")
		}
	}

	if *routeFile != "" {
		if *configFile != "" || len(listenFlags) > 0 || len(forwardFlags) > 0 {
			return config.Config{}, subOpts, fmt.Errorf("-R cannot be used with -C/-L/-F")
		}
		cfg, err := parseRouteConfig(*routeFile)
		if err != nil {
			return config.Config{}, subOpts, err
		}
		applyDebugFlags(&cfg, *isDebug, *isDebugVerbose)
		cfg.RoutePath = *routeFile
		return cfg, subOpts, nil
	}

	if *configFile != "" {
		cfg, err := parseConfigFile(*configFile)
		if err != nil {
			return config.Config{}, subOpts, err
		}
		applyDebugFlags(&cfg, *isDebug, *isDebugVerbose)
		return cfg, subOpts, nil
	}

	logLevel := "info"
	if (isDebug != nil && *isDebug) || (isDebugVerbose != nil && *isDebugVerbose) {
		logLevel = "debug"
	}

	cfg := config.Config{}

	llevel, err := logging.ParseLevel(logLevel)
	if err != nil {
		return config.Config{}, subOpts, err
	}
	logger := logging.New(logging.Options{Level: llevel})
	cfg.Logger = logger
	cfg.LogLevel = llevel
	cfg.DebugVerbose = isDebugVerbose != nil && *isDebugVerbose

	// 订阅模式不需要 listen 参数
	if len(subOpts.URLs) == 0 && (tproxyPort == nil || *tproxyPort == 0) && len(listenFlags) == 0 {
		defaultPath, err := cjson.FindDefaultConfig()
		if err != nil {
			fs.Usage()
			return cfg, subOpts, err
		}
		dcfg, err := parseConfigFile(defaultPath)
		if err != nil {
			return config.Config{}, subOpts, err
		}
		applyDebugFlags(&dcfg, *isDebug, *isDebugVerbose)
		return dcfg, subOpts, nil
	}

	if tproxyPort != nil && *tproxyPort > 0 {
		addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(*tproxyPort))
		ep, err := endpoint.Parse("tproxy://" + addr)
		if err != nil {
			return cfg, subOpts, fmt.Errorf("parse -T %d: %w", *tproxyPort, err)
		}
		cfg.Listeners = append(cfg.Listeners, ep)
		cfg.Listen = ep
		cfg.TProxy = &config.TProxyConfig{
			Port:         *tproxyPort,
			Network:      []string{"tcp"},
			Sniffing:     true,
			DestOverride: []string{"http", "tls", "quic"},
		}
	} else if len(listenFlags) > 0 {
		listeners, idx, err := config.ParseEndpoints(listenFlags)
		if err != nil {
			return cfg, subOpts, fmt.Errorf("parse -L %s: %w", listenFlags[idx], err)
		}
		cfg.Listeners = append(cfg.Listeners, listeners...)
		cfg.Listen = cfg.Listeners[0]
	}

	if len(forwardFlags) > 0 {
		chain, idx, err := config.ParseEndpoints(forwardFlags)
		if err != nil {
			return cfg, subOpts, fmt.Errorf("parse -F %s: %w", forwardFlags[idx], err)
		}
		cfg.ForwardChain = append(cfg.ForwardChain, chain...)
		if len(cfg.ForwardChain) > 0 {
			last := cfg.ForwardChain[len(cfg.ForwardChain)-1]
			cfg.Forward = &last
		}
	}

	cfg.Insecure = *insecure

	if len(cfg.Listeners) > 0 {
		cfg.Nodes = []config.NodeConfig{{
			Name:          "default",
			Listeners:     cfg.Listeners,
			Forward:       cfg.Forward,
			ForwardChain:  cfg.ForwardChain,
			Insecure:      cfg.Insecure,
			SubscribeURL:  primarySubscribeURL(subOpts.URLs),
			SubscribeURLs: subOpts.URLs,
		}}
	}

	config.ApplyDefaults(&cfg)
	cfg.SubscribeURL = primarySubscribeURL(subOpts.URLs)
	cfg.SubscribeURLs = subOpts.URLs
	cfg.SubscribeFilter = subOpts.Filter
	cfg.SubscribeUpdate = subOpts.Update
	return cfg, subOpts, nil
}

func splitSubscribeValues(values []string) []string {
	return config.NormalizeSubscribeURLs("", config.SplitCSVValues(values))
}

func primarySubscribeURL(urls []string) string {
	return config.PrimaryValue(urls)
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

func applyDebugFlags(cfg *config.Config, debug, debugVerbose bool) {
	if cfg == nil {
		return
	}
	if cfg.Logger == nil {
		cfg.Logger = logging.New(logging.Options{Level: logging.LevelInfo})
		cfg.LogLevel = logging.LevelInfo
	}
	if debug || debugVerbose {
		cfg.Logger.SetLevel(logging.LevelDebug)
		cfg.LogLevel = logging.LevelDebug
	}
	if debugVerbose {
		cfg.DebugVerbose = true
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
