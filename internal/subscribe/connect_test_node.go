package subscribe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"forward/base/endpoint"
	"forward/base/logging"
	"forward/internal/builder"
	"forward/internal/config"
	"forward/internal/chain"
)

const (
	testRounds     = 3  // 每个节点测试轮次（第 1 轮作为热身，取后续最优值）
	maxConcurrency = 10 // 最大并发数
)

// TestNodes 并发测试节点延迟，最多 10 个节点同时测试，每个节点测试 3 次取最优。
// 输出格式: time Forward Subscribe Connect Test Node-[节点名] 协议类型 延迟 ms
func TestNodes(ctx context.Context, proxies []ClashProxy, connectURL string, cfg config.Config, logger *logging.Logger) {
	if connectURL == "" {
		connectURL = "http://www.gstatic.com/generate_204"
	}

	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

loop:
	for _, proxy := range proxies {
		select {
		case <-ctx.Done():
			break loop
		default:
		}

		ep, err := ProxyToEndpoint(proxy)
		if err != nil {
			logger.Warn("Node-[%s] 转换失败: %v", proxy.Name, err)
			continue
		}

		wg.Add(1)
		go func(p ClashProxy, ep endpoint.Endpoint) {
			defer wg.Done()

			// 获取信号量
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			// 构建路由只做一次，多轮测试复用
			hops := []endpoint.Endpoint{ep}
			rt, err := builder.BuildRoute(cfg, hops)
			if err != nil {
				fmt.Printf("%s Forward Subscribe Connect Test Node-[%s] %s error: 构建路由失败: %v\n",
					time.Now().Format("15:04:05"),
					p.Name,
					p.Type,
					err,
				)
				return
			}

			var bestLatency time.Duration
			var lastErr error

			for round := 0; round < testRounds; round++ {
				select {
				case <-ctx.Done():
					return
				default:
				}

				latency, err := testNodeLatency(ctx, rt, connectURL)
				if err != nil {
					lastErr = err
					continue
				}
				if bestLatency == 0 || latency < bestLatency {
					bestLatency = latency
				}
			}

			if bestLatency == 0 {
				fmt.Printf("%s Forward Subscribe Connect Test Node-[%s] %s timeout/error: %v\n",
					time.Now().Format("15:04:05"),
					p.Name,
					p.Type,
					lastErr,
				)
				return
			}

			fmt.Printf("%s Forward Subscribe Connect Test Node-[%s] %s %d ms\n",
				time.Now().Format("15:04:05"),
				p.Name,
				p.Type,
				bestLatency.Milliseconds(),
			)
		}(proxy, ep)
	}

	wg.Wait()
}

// testNodeLatency 通过已构建的路由发起请求测量单次延迟。
func testNodeLatency(ctx context.Context, rt chain.Route, connectURL string) (time.Duration, error) {
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	start := time.Now()

	// 通过转发链拨号
	conn, err := rt.Dial(testCtx, "tcp", extractHostFromURL(connectURL))
	if err != nil {
		return 0, fmt.Errorf("连接失败: %w", err)
	}
	defer conn.Close()

	// 通过连接发送 HTTP 请求
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn, nil
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	req, err := http.NewRequestWithContext(testCtx, http.MethodGet, connectURL, nil)
	if err != nil {
		return 0, fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	latency := time.Since(start)
	return latency, nil
}

// extractHostFromURL 从 URL 中提取 host:port。
func extractHostFromURL(rawURL string) string {
	// 简单解析
	// http://www.gstatic.com/generate_204 -> www.gstatic.com:80
	// https://example.com/path -> example.com:443
	if len(rawURL) > 8 && rawURL[:8] == "https://" {
		rest := rawURL[8:]
		host := rest
		if idx := indexByte(host, '/'); idx >= 0 {
			host = host[:idx]
		}
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = host + ":443"
		}
		return host
	}
	if len(rawURL) > 7 && rawURL[:7] == "http://" {
		rest := rawURL[7:]
		host := rest
		if idx := indexByte(host, '/'); idx >= 0 {
			host = host[:idx]
		}
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = host + ":80"
		}
		return host
	}
	return rawURL
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
