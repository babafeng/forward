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
	"time"

	"forward/internal/config"
	"forward/internal/endpoint"
	"forward/internal/logging"
	rc "forward/internal/reverse/client"
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

	if cfg.Insecure {
		logger.Warn("The --insecure is enabled will trust any cert: TLS verification is disabled")
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(cfg.Listeners))

	for _, l := range cfg.Listeners {
		wg.Add(1)
		subCfg := cfg
		subCfg.Listen = l
		go func(c config.Config) {
			defer wg.Done()
			if err := runOne(ctx, c); err != nil {
				logger.Error("Error running listener %s: %v", c.Listen.String(), err)
				errChan <- err
				stop()
			}
		}(subCfg)
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return 1
	}

	return 0
}

func runOne(ctx context.Context, cfg config.Config) error {
	if isReverseForwardClient(cfg) {
		return runReverseClient(ctx, cfg)
	}

	if isPortForward(cfg) {
		return runPortForward(ctx, cfg)
	}

	if isProxyServer(cfg) {
		return runProxyServer(ctx, cfg)
	}

	if isReverseForwardServer(cfg) {
		return runReverseServer(ctx, cfg)
	}

	return nil
}

func runReverseClient(ctx context.Context, cfg config.Config) error {
	cfg.Mode = config.ModeReverseClient
	cfg.IsReverseClient = true
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
	cfg.IsPortForward = true
	if cfg.Forward == nil {
		ef, _ := endpoint.Parse(fmt.Sprintf("%s://%s", cfg.Listen.Scheme, cfg.Listen.FAddress))
		cfg.Forward = &ef
	}
	_, err := runForwarders(ctx, cfg)
	return err
}

func runProxyServer(ctx context.Context, cfg config.Config) error {
	if cfg.Proxy == nil && cfg.Forward != nil && cfg.Listen.FAddress == "" {
		cfg.Proxy = cfg.Forward
		cfg.Forward = nil
	}
	cfg.Mode = config.ModeProxyServer
	cfg.IsProxyServer = true
	_, err := runForwarders(ctx, cfg)
	return err
}

func runReverseServer(ctx context.Context, cfg config.Config) error {
	cfg.Mode = config.ModeReverseServer
	cfg.IsReverseServer = true
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
	forward := fs.String("F", "", "Forward target endpoint, e.g. https://remote.com:443")
	proxy := fs.String("x", "", "Optional proxy endpoint, e.g. socks5://127.0.0.1:1080")
	insecure := fs.Bool("insecure", false, "Disable TLS certificate verification")
	isDebug := fs.Bool("debug", true, "Enable debug logging")
	isVersion := fs.Bool("version", false, "Show version information")
	dialTimeout := fs.Duration("dial-timeout", 10*time.Second, "Dial timeout")
	dialKeepAlive := fs.Duration("dial-keepalive", 30*time.Second, "Dial keepalive")

	fs.Usage = func() { Usage(fs) }

	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
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

	logger.Info("Forward %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if *isVersion {
		return config.Config{}, nil
	}

	if len(listenFlags) == 0 {
		fs.Usage()
		return cfg, fmt.Errorf("-L is required")
	}

	for _, l := range listenFlags {
		ep, err := endpoint.Parse(l)
		if err != nil {
			return cfg, fmt.Errorf("parse -L %s: %w", l, err)
		}
		cfg.Listeners = append(cfg.Listeners, ep)
	}
	cfg.Listen = cfg.Listeners[0]

	if strings.TrimSpace(*forward) != "" {
		ef, err := endpoint.Parse(*forward)
		if err != nil {
			return cfg, fmt.Errorf("parse -F: %w", err)
		}
		cfg.Forward = &ef
	}

	if strings.TrimSpace(*proxy) != "" {
		ep, err := endpoint.Parse(*proxy)
		if err != nil {
			return cfg, fmt.Errorf("parse -x: %w", err)
		}
		cfg.Proxy = &ep
	}

	cfg.UDPIdleTimeout = 2 * time.Minute
	cfg.Insecure = *insecure
	cfg.DialTimeout = *dialTimeout
	cfg.DialKeepAlive = *dialKeepAlive

	return cfg, nil
}

func isProxyServer(cfg config.Config) bool {
	switch strings.ToLower(cfg.Listen.Scheme) {
	case "http", "https", "http3", "socks5", "tls", "quic":
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
	switch strings.ToLower(cfg.Listen.Scheme) {
	case "tls", "http3", "https", "quic":
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
	fmt.Fprintf(fs.Output(), `
Examples:
  1. Port Forwarding
     # Forward TCP: local 8080 -> 1.2.3.4:80
     forward -L tcp://:8080/1.2.3.4:80
     forward -L tcp://:8080 -F tcp://1.2.3.4:80

     # Forward UDP: local 5353 -> 8.8.8.8:53
     forward -L udp://:5353/8.8.8.8:53
     forward -L udp://:5353 -F udp://8.8.8.8:53

     # Forward with Proxy (Chain)
     forward -L tcp://:8080/1.2.3.4:80 -x socks5://proxy.com:1080
     forward -L tcp://:8080/1.2.3.4:80 -x tls://proxy.com:1080

  2. Proxy Server
     # Start HTTP/SOCKS5/TLS/QUIC server
     forward -L http://:1080
     forward -L socks5://:1080
     forward -L tls://:1080?cert=server.crt&key=server.key
     forward -L quic://:1080?cert=server.crt&key=server.key

     # With Authentication
     forward -L socks5://user:pass@:1080

  3. Intranet Penetration (Reverse Proxy)
     # Server (Public IP)
     forward -L tls://:2333?bind=true&cert=server.crt&key=server.key

     # Client (Intranet)
     # Map remote 2222 on server -> local 22
     forward -L tcp://:2222//127.0.0.1:22 -F tls://server.com:2333?ca=self-rootca.cer

  4. Multiple Listeners
     forward -L tcp://:8080/1.2.3.4:80 -L socks5://:1080

Flags:
`)
}

type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}
