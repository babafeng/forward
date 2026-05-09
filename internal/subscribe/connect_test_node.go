package subscribe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"forward/base/endpoint"
	"forward/base/logging"
	"forward/internal/builder"
	"forward/internal/chain"
	"forward/internal/config"
)

const (
	warmupRounds   = 1
	measureRounds  = 2
	testRounds     = warmupRounds + measureRounds // 每个节点测试轮次（热身轮不计入结果，取测量轮最优值）
	maxConcurrency = 10                           // 最大并发数
)

type nodeTestResult struct {
	Name    string
	Type    string
	Latency time.Duration
	Err     error
	At      time.Time
}

type nodeTestSummary struct {
	Successes []nodeTestResult
	Failures  []nodeTestResult
}

// TestNodes 并发测试节点延迟，最多 10 个节点同时测试，每个节点测试 3 次取最优。
// 成功结果实时输出，失败结果在末尾集中输出，避免失败日志打断可用节点排查。
func TestNodes(ctx context.Context, proxies []ClashProxy, connectURL string, cfg config.Config, logger *logging.Logger) {
	if connectURL == "" {
		connectURL = "http://www.gstatic.com/generate_204"
	}

	sem := make(chan struct{}, maxConcurrency)
	results := make(chan nodeTestResult, len(proxies))
	summaryCh := make(chan nodeTestSummary, 1)
	go collectNodeTestResults(results, summaryCh)
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
			results <- nodeTestResult{
				Name: proxy.Name,
				Type: proxy.Type,
				Err:  fmt.Errorf("转换失败: %w", err),
				At:   time.Now(),
			}
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
				results <- nodeTestResult{
					Name: p.Name,
					Type: p.Type,
					Err:  fmt.Errorf("构建路由失败: %w", err),
					At:   time.Now(),
				}
				return
			}

			bestLatency, err := testNodeBestLatency(ctx, rt, connectURL)
			if err != nil {
				results <- nodeTestResult{
					Name: p.Name,
					Type: p.Type,
					Err:  err,
					At:   time.Now(),
				}
				return
			}

			results <- nodeTestResult{
				Name:    p.Name,
				Type:    p.Type,
				Latency: bestLatency,
				At:      time.Now(),
			}
		}(proxy, ep)
	}

	wg.Wait()
	close(results)
	printNodeTestSummary(<-summaryCh)
}

func collectNodeTestResults(results <-chan nodeTestResult, summaryCh chan<- nodeTestSummary) {
	summary := nodeTestSummary{}

	for result := range results {
		if result.Err != nil {
			summary.Failures = append(summary.Failures, result)
			continue
		}
		summary.Successes = append(summary.Successes, result)
		fmt.Printf("%s Forward Subscribe Connect Test OK Node-[%s] %s %d ms\n",
			result.At.Format("15:04:05"),
			result.Name,
			result.Type,
			result.Latency.Milliseconds(),
		)
	}
	summaryCh <- summary
}

func printNodeTestSummary(summary nodeTestSummary) {
	sort.SliceStable(summary.Successes, func(i, j int) bool {
		return summary.Successes[i].Latency < summary.Successes[j].Latency
	})
	sort.SliceStable(summary.Failures, func(i, j int) bool {
		if summary.Failures[i].Type == summary.Failures[j].Type {
			return summary.Failures[i].Name < summary.Failures[j].Name
		}
		return summary.Failures[i].Type < summary.Failures[j].Type
	})

	if len(summary.Successes) > 0 {
		fmt.Printf("\nForward Subscribe Connect Test Success (%d, sorted by latency):\n", len(summary.Successes))
		for i, result := range summary.Successes {
			fmt.Printf("%2d. Node-[%s] %s %d ms\n",
				i+1,
				result.Name,
				result.Type,
				result.Latency.Milliseconds(),
			)
		}
	}

	if len(summary.Failures) > 0 {
		fmt.Printf("\nForward Subscribe Connect Test Failed (%d):\n", len(summary.Failures))
		for i, result := range summary.Failures {
			fmt.Printf("%2d. Node-[%s] %s timeout/error: %v\n",
				i+1,
				result.Name,
				result.Type,
				result.Err,
			)
		}
	}
}

func isWarmupRound(round int) bool {
	return round < warmupRounds
}

// testNodeBestLatency 复用同一条 HTTP keep-alive 连接测速。
// 第一轮用于建立代理链路和预热目标 URL，不计入最终结果。
func testNodeBestLatency(ctx context.Context, rt chain.Route, connectURL string) (time.Duration, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := rt.Dial(ctx, "tcp", addr)
			if err != nil {
				return nil, fmt.Errorf("连接失败: %w", err)
			}
			return conn, nil
		},
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	var bestLatency time.Duration
	var lastErr error
	for round := 0; round < testRounds; round++ {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}

		latency, err := testNodeLatency(ctx, client, connectURL)
		if err != nil {
			lastErr = err
			continue
		}
		if isWarmupRound(round) {
			continue
		}
		if bestLatency == 0 || latency < bestLatency {
			bestLatency = latency
		}
	}
	if bestLatency == 0 {
		if lastErr != nil {
			return 0, lastErr
		}
		return 0, fmt.Errorf("no measured latency")
	}
	return bestLatency, nil
}

// testNodeLatency 通过已构建的 HTTP client 发起请求测量单次延迟。
func testNodeLatency(ctx context.Context, client *http.Client, connectURL string) (time.Duration, error) {
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(testCtx, http.MethodGet, connectURL, nil)
	if err != nil {
		return 0, fmt.Errorf("创建请求失败: %w", err)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return 0, fmt.Errorf("读取响应失败: %w", err)
	}

	latency := time.Since(start)
	return latency, nil
}

// extractHostFromURL 从 URL 中提取 host:port，供 Dial 使用。
func extractHostFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}
