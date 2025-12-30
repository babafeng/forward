package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"go-forward/core/forward"
	"go-forward/core/proxy"
	"go-forward/core/reverse"
	"go-forward/core/utils"
)

// StringArray 实现 flag.Value 接口用于支持多个 -L 和 -F 参数
type StringArray []string

func (s *StringArray) String() string {
	return strings.Join(*s, ",")
}

func (s *StringArray) Set(value string) error {
	*s = append(*s, value)
	return nil
}

var (
	listenFlags  StringArray
	forwardFlag  string
	verbose      bool
	veryVerbose  bool
	printVersion bool
	insecureFlag bool
)

var allSchemes = map[string]struct{}{
	"socks5":  {},
	"http":    {},
	"http2":   {},
	"http3":   {},
	"https":   {},
	"http1.1": {},
	"tls":     {},
	"ssh":     {},
	"tcp":     {},
	"udp":     {},
	"quic":    {},
}

var proxySchemes = map[string]struct{}{
	"socks5":  {},
	"http":    {},
	"http2":   {},
	"http1.1": {},
	"http3":   {},
	"https":   {},
	"tls":     {},
	"ssh":     {},
	"quic":    {},
}

func main() {
	flag.Var(&listenFlags, "L", "Listen address (e.g., tls://:443, socks5://:1080)")
	flag.StringVar(&forwardFlag, "F", "", "Forward address (e.g., tls://server:1080)")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging (info, warn, error)")
	flag.BoolVar(&veryVerbose, "vv", false, "Enable very verbose logging (debug, info, warn, error)")
	flag.BoolVar(&printVersion, "V", false, "print version")
	flag.BoolVar(&insecureFlag, "insecure", false, "Allow insecure SSL/TLS connections")
	flag.Parse()

	fmt.Fprintf(os.Stdout, "forward %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if printVersion {
		os.Exit(0)
	}

	// 配置日志级别：默认 info，-v 开启 warn，-vv 开启 debug
	switch {
	case veryVerbose:
		utils.SetLevel(utils.LevelDebug)
	case verbose:
		utils.SetLevel(utils.LevelWarn)
	default:
		utils.SetLevel(utils.LevelInfo)
	}

	utils.SetInsecure(insecureFlag)

	if len(listenFlags) == 0 {
		flag.Usage()
		return
	}

	utils.Info("Starting forward...")

	// 启动所有监听器
	for _, listen := range listenFlags {
		go startListener(listen, forwardFlag)
	}

	// 等待退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	utils.Info("Shutting down...")
}

func startListener(listenURL string, forwardURL string) {
	utils.Info("Initializing listener: %s", utils.RedactURL(listenURL))

	scheme, _, _ := utils.URLParse(listenURL)
	if scheme != "" {
		if _, exists := allSchemes[scheme]; !exists {
			utils.Error("Unsupported scheme: %s", scheme)
			utils.Info("Shutting down...")
			os.Exit(0)
		}
	}

	// Redact forward URLs for logging
	var redactedForwardURL string
	if forwardURL != "" {
		redactedForwardURL = utils.RedactURL(forwardURL)
	}

	if strings.Contains(listenURL, "bind=true") {
		utils.Info("Forward enabled reverse server mode for %s", utils.RedactURL(listenURL))
		go reverse.StartServer(listenURL)

	} else if forwardURL != "" && (strings.HasPrefix(listenURL, "tcp://") || strings.HasPrefix(listenURL, "udp://")) {
		if isReverseClient(listenURL, forwardURL) {
			utils.Info("Forward starting reverse client for %s", utils.RedactURL(listenURL))
			go reverse.StartClient(listenURL, forwardURL)

		} else if isPortForward(listenURL) {
			utils.Info("Forward starting port forward for %s via %s", utils.RedactURL(listenURL), redactedForwardURL)
			go forward.Start(listenURL, forwardURL)

		} else {
			utils.Info("Forward proxy for %s", utils.RedactURL(listenURL))
			go proxy.Start(listenURL, forwardURL)

		}
	} else if isPortForward(listenURL) {
		utils.Info("Forward starting port forward for %s via %s", utils.RedactURL(listenURL), redactedForwardURL)
		go forward.Start(listenURL, forwardURL)

	} else {
		if scheme != "" {
			if _, exists := proxySchemes[scheme]; !exists {
				utils.Error("Unsupported proxy scheme: %s", scheme)
				utils.Info("Shutting down...")
				os.Exit(0)
			}
		}

		if len(strings.Split(listenURL, "//")) > 2 {
			utils.Error("Unsupported : %s", scheme)
			utils.Info("Shutting down...")
			os.Exit(0)
		}

		utils.Info("Forward proxy for %s", utils.RedactURL(listenURL))
		go proxy.Start(listenURL, forwardURL)
	}
}

func isReverseClient(listenURL string, forwardURL string) bool {
	// 内网穿透（如 tcp://8080//1.2.3.4:80）少了一个冒号

	parts := strings.Split(listenURL, "//")

	if len(parts) != 3 {
		return false
	}

	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	if forwardURL == "" {
		return false
	}

	scheme, _, _ := utils.URLParse(listenURL)

	if scheme != "tcp" && scheme != "udp" {
		return false
	}

	if port < 1 || port > 65535 {
		return false
	}

	if !utils.IsValidHostPort(parts[2]) {
		return false
	}

	return true
}

func isPortForward(listenURL string) bool {
	parts := strings.Split(listenURL, "//")
	scheme, _, _ := utils.URLParse(listenURL)

	if scheme != "tcp" && scheme != "udp" {
		return false
	}

	// 需要有三部分（如 tcp://:8080//1.2.3.4:80）表示是转发
	// 另外内网穿透是（如 tcp://8080//1.2.3.4:80）少了一个冒号
	if len(parts) != 3 {
		return false
	}

	if !strings.Contains(parts[1], ":") {
		return false
	}

	if !utils.IsValidHostPort(parts[2]) {
		return false
	}

	return true
}
