package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
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

	utils.Info("Starting go-forward...")

	// 启动所有监听器
	for _, l := range listenFlags {
		go startListener(l, forwardFlags)
	}

	// 等待退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	utils.Info("Shutting down...")
}

func startListener(listenURL string, forwardURLs []string) {
	utils.Info("Initializing listener: %s", listenURL)
	if strings.Contains(listenURL, "bind=true") {
		go reverse.StartServer(listenURL)
	} else if len(forwardURLs) > 0 && (strings.HasPrefix(listenURL, "tcp://") || strings.HasPrefix(listenURL, "udp://")) {
		if isReverseClient(listenURL, forwardURLs) {
			go reverse.StartClient(listenURL, forwardURLs)
		} else if isPortForward(listenURL) {
			go forward.Start(listenURL, forwardURLs)
		} else {
			go proxy.Start(listenURL, forwardURLs)
		}
	} else if isPortForward(listenURL) {
		go forward.Start(listenURL, forwardURLs)
	} else {
		go proxy.Start(listenURL, forwardURLs)
	}
}

func isReverseClient(listenURL string, forwardURLs []string) bool {
	if len(forwardURLs) == 0 {
		return false
	}
	if !isPortForward(listenURL) {
		return false
	}

	s := listenURL
	if strings.HasPrefix(s, "tcp://") {
		s = strings.TrimPrefix(s, "tcp://")
	} else if strings.HasPrefix(s, "udp://") {
		s = strings.TrimPrefix(s, "udp://")
	}

	parts := strings.Split(s, "//")
	if len(parts) < 2 {
		return false
	}
	localPart := parts[0]

	// ":" 表示本地绑定地址 -> 端口转发
	if strings.HasPrefix(localPart, ":") {
		return false
	}
	// "." 表示 IP 地址 -> 端口转发
	if strings.Contains(localPart, ".") {
		return false
	}

	// 否则为远程端口 -> 反向代理客户端
	return true
}

func isPortForward(listenURL string) bool {
	parts := strings.Split(listenURL, "//")

	// 超过 2 部分（如 tcp://:8080//target）表示是转发
	if len(parts) > 2 {
		return true
	}

	if len(parts) == 2 {
		s := strings.ToLower(parts[0])
		// 检查是否为已知的代理协议
		proxySchemes := map[string]struct{}{
			"socks5:": {},
			"http:":   {},
			"https:":  {},
			"tls:":    {},
			"ssh:":    {},
			"tcp:":    {},
			"udp:":    {},
			"quic:":   {},
		}
		if _, exists := proxySchemes[s]; exists {
			return false
		}
		return true
	}

	return false
}
