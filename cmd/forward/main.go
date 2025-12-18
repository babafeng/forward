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
	forwardFlags StringArray
	logLevel     string
	printVersion bool
)

var allSchemes = map[string]struct{}{
	"socks5": {},
	"http":   {},
	"https":  {},
	"tls":    {},
	"ssh":    {},
	"tcp":    {},
	"udp":    {},
	"quic":   {},
}

var proxySchemes = map[string]struct{}{
	"socks5": {},
	"http":   {},
	"https":  {},
	"tls":    {},
	"ssh":    {},
	"quic":   {},
}

func main() {
	flag.Var(&listenFlags, "L", "Listen address (e.g., tls://:443, socks5://:1080)")
	flag.Var(&forwardFlags, "F", "Forward address (e.g., tls://server:1080)")
	flag.BoolVar(&printVersion, "V", false, "print version")
	flag.Parse()

	if printVersion {
		fmt.Fprintf(os.Stdout, "forward %s (%s %s/%s)\n",
			version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	logLevel = "info"
	// 配置日志级别
	switch strings.ToLower(logLevel) {
	case "debug":
		utils.SetLevel(utils.LevelDebug)
	case "warn":
		utils.SetLevel(utils.LevelWarn)
	case "error":
		utils.SetLevel(utils.LevelError)
	default:
		utils.SetLevel(utils.LevelInfo)
	}

	if len(listenFlags) == 0 {
		flag.Usage()
		return
	}

	utils.Info("Starting forward...")

	// 启动所有监听器
	for _, listen := range listenFlags {
		go startListener(listen, forwardFlags)
	}

	// 等待退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	utils.Info("Shutting down...")
}

func startListener(listenURL string, forwardURLs []string) {
	utils.Info("Initializing listener: %s", listenURL)

	scheme, _, _ := utils.URLParse(listenURL)
	if scheme != "" {
		if _, exists := allSchemes[scheme]; !exists {
			utils.Logging("Unsupported scheme: %s", scheme)
			utils.Info("Shutting down...")
			os.Exit(0)
		}
	}

	if strings.Contains(listenURL, "bind=true") {
		utils.Logging("Forward enabled reverse server mode for %s", listenURL)
		go reverse.StartServer(listenURL)

	} else if len(forwardURLs) > 0 && (strings.HasPrefix(listenURL, "tcp://") || strings.HasPrefix(listenURL, "udp://")) {
		if isReverseClient(listenURL, forwardURLs) {
			utils.Logging("Forward starting reverse client for %s", listenURL)
			go reverse.StartClient(listenURL, forwardURLs)

		} else if isPortForward(listenURL) {
			utils.Logging("Forward starting port forward for %s via %v", listenURL, forwardURLs)
			go forward.Start(listenURL, forwardURLs)

		} else {
			utils.Logging("Forward proxy for %s", listenURL)
			go proxy.Start(listenURL, forwardURLs)

		}
	} else if isPortForward(listenURL) {
		utils.Logging("Forward starting port forward for %s via %v", listenURL, forwardURLs)
		go forward.Start(listenURL, forwardURLs)

	} else {
		if scheme != "" {
			if _, exists := proxySchemes[scheme]; !exists {
				utils.Logging("Unsupported proxy scheme: %s", scheme)
				utils.Info("Shutting down...")
				os.Exit(0)
			}
		}

		if len(strings.Split(listenURL, "//")) > 2 {
			utils.Logging("Unsupported : %s", scheme)
			utils.Info("Shutting down...")
			os.Exit(0)
		}

		utils.Logging("Forward proxy for %s", listenURL)
		go proxy.Start(listenURL, forwardURLs)
	}
}

func isReverseClient(listenURL string, forwardURLs []string) bool {
	// 内网穿透（如 tcp://8080//1.2.3.4:80）少了一个冒号

	parts := strings.Split(listenURL, "//")

	if len(parts) != 3 {
		return false
	}

	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	if len(forwardURLs) == 0 {
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
