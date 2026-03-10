package app

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"forward/base/logging"
	"forward/internal/config"
	"forward/internal/subscribe"
)

func loadSubscribeProxies(urls []string, logger *logging.Logger) ([]subscribe.ClashProxy, error) {
	urls = config.NormalizeSubscribeURLs("", urls)
	if len(urls) == 0 {
		return nil, fmt.Errorf("no subscription sources configured")
	}

	var (
		proxies []subscribe.ClashProxy
		errors  []string
	)

	for _, subURL := range urls {
		if logger != nil {
			logger.Info("Downloading subscription from %s", subURL)
		}
		data, err := subscribeDownload(subURL)
		if err != nil {
			if logger != nil {
				logger.Warn("Failed to download subscription from %s: %v", subURL, err)
			}
			errors = append(errors, fmt.Sprintf("%s: %v", subURL, err))
			continue
		}

		subProxies, err := subscribe.Parse(data)
		if err != nil {
			if logger != nil {
				logger.Warn("Failed to parse subscription from %s: %v", subURL, err)
			}
			errors = append(errors, fmt.Sprintf("%s: %v", subURL, err))
			continue
		}
		proxies = append(proxies, subProxies...)
	}

	if len(proxies) == 0 {
		if len(errors) == 0 {
			return nil, fmt.Errorf("no valid matching nodes in subscription")
		}
		return nil, fmt.Errorf("download subscribe nodes: all subscription sources failed: %s", strings.Join(errors, "; "))
	}

	return proxies, nil
}

func dedupeSubscribeProxies(proxies []subscribe.ClashProxy) []subscribe.ClashProxy {
	seen := make(map[string]struct{}, len(proxies))
	deduped := make([]subscribe.ClashProxy, 0, len(proxies))
	for _, proxy := range proxies {
		key := subscribeProxyKey(proxy)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, proxy)
	}
	return deduped
}

func subscribeProxyKey(proxy subscribe.ClashProxy) string {
	hostHeader := ""
	if proxy.WSOpts != nil {
		hostHeader = proxy.WSOpts.Headers["Host"]
	}

	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(proxy.Type)),
		strings.ToLower(strings.TrimSpace(proxy.Server)),
		strconv.Itoa(proxy.Port),
		strings.TrimSpace(proxy.UUID),
		strconv.Itoa(proxy.AlterID),
		strings.TrimSpace(proxy.Cipher),
		strconv.FormatBool(proxy.UDP),
		strings.TrimSpace(proxy.Password),
		strconv.FormatBool(proxy.TLS),
		strings.TrimSpace(proxy.SNI),
		strings.ToLower(strings.TrimSpace(proxy.Network)),
		strings.TrimSpace(hostHeader),
		func() string {
			if proxy.WSOpts == nil {
				return ""
			}
			return strings.TrimSpace(proxy.WSOpts.Path)
		}(),
	}, "\x00")
}

// subscribeOptions 保存订阅模式相关的选项。
type subscribeOptions struct {
	URLs       []string
	Filter     string
	Update     int
	ConnectURL string
}

func runSubscribe(ctx context.Context, opts subscribeOptions, cfg config.Config, logger *logging.Logger) int {
	logger.Info("开始处理订阅源: %s", describeSubscribeSources(opts.URLs))

	var (
		proxies []subscribe.ClashProxy
		errors  []string
	)

	for _, subURL := range config.NormalizeSubscribeURLs("", opts.URLs) {
		logger.Info("开始下载订阅链接: %s", subURL)

		data, err := subscribeDownload(subURL)
		if err != nil {
			logger.Warn("下载订阅链接失败: %s: %v", subURL, err)
			errors = append(errors, fmt.Sprintf("%s: %v", subURL, err))
			continue
		}
		logger.Info("订阅内容下载完成，大小: %d 字节", len(data))

		savedPath, err := subscribe.SaveToFile(data, subURL)
		if err != nil {
			logger.Warn("保存订阅文件失败: %s: %v", subURL, err)
		} else {
			logger.Info("订阅文件已保存到: %s", savedPath)
		}

		subProxies, err := subscribe.Parse(data)
		if err != nil {
			logger.Warn("解析订阅内容失败: %s: %v", subURL, err)
			errors = append(errors, fmt.Sprintf("%s: %v", subURL, err))
			continue
		}
		logger.Info("订阅 %s 解析到 %d 个代理节点", subURL, len(subProxies))
		proxies = append(proxies, subProxies...)
	}

	if len(proxies) == 0 {
		if len(errors) == 0 {
			logger.Error("没有可用的订阅节点")
		} else {
			logger.Error("所有订阅源都处理失败: %s", strings.Join(errors, "; "))
		}
		return 1
	}

	logger.Info("聚合后共解析到 %d 个代理节点", len(proxies))

	// 过滤节点
	if opts.Filter != "" {
		proxies = subscribe.FilterProxies(proxies, opts.Filter)
		logger.Info("过滤后剩余 %d 个代理节点", len(proxies))
	}
	proxies = dedupeSubscribeProxies(proxies)
	logger.Info("去重后剩余 %d 个代理节点", len(proxies))

	if len(proxies) == 0 {
		logger.Warn("没有匹配的代理节点")
		return 0
	}

	// 测试节点延迟
	connectURL := opts.ConnectURL
	if connectURL == "" {
		connectURL = defaultConnectURL
	}
	logger.Info("开始测试 %d 个节点延迟，测试目标: %s", len(proxies), connectURL)
	subscribe.TestNodes(ctx, proxies, connectURL, cfg, logger)

	return 0
}

func describeSubscribeSources(urls []string) string {
	urls = config.NormalizeSubscribeURLs("", urls)
	switch len(urls) {
	case 0:
		return "0 subscription sources"
	case 1:
		return urls[0]
	case 2, 3:
		return strings.Join(urls, ", ")
	default:
		return fmt.Sprintf("%d subscription sources", len(urls))
	}
}
