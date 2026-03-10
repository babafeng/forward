package app

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"forward/base/endpoint"
	"forward/base/logging"
	"forward/internal/chain"
	"forward/internal/config"
	"forward/internal/listener"
	"forward/internal/subscribe"

	ctls "forward/internal/config/tls"

	_ "forward/internal/connector/http"
	_ "forward/internal/connector/http2"
	_ "forward/internal/connector/http3"
	_ "forward/internal/connector/hysteria2"
	_ "forward/internal/connector/socks5"
	_ "forward/internal/connector/tcp"
	_ "forward/internal/dialer/dtls"
	_ "forward/internal/dialer/h2"
	_ "forward/internal/dialer/h3"
	_ "forward/internal/dialer/http3"
	_ "forward/internal/dialer/hysteria2"
	_ "forward/internal/dialer/quic"
	_ "forward/internal/dialer/tcp"
	_ "forward/internal/dialer/tls"
	_ "forward/internal/dialer/udp"
	_ "forward/internal/dialer/ws"
	_ "forward/internal/handler/http"
	_ "forward/internal/handler/reverse"
	_ "forward/internal/handler/socks5"
	_ "forward/internal/handler/tcp"
	_ "forward/internal/handler/tproxy"
	_ "forward/internal/handler/udp"
	_ "forward/internal/listener/dtls"
	_ "forward/internal/listener/h2"
	_ "forward/internal/listener/h3"
	_ "forward/internal/listener/http3"
	_ "forward/internal/listener/quic"
	_ "forward/internal/listener/tcp"
	_ "forward/internal/listener/tproxy"
	_ "forward/internal/listener/udp"

	// VLESS + Reality
	_ "forward/internal/connector/vless"
	_ "forward/internal/dialer/reality"
	_ "forward/internal/handler/vless"
	_ "forward/internal/listener/reality"

	// VMess
	_ "forward/internal/connector/vmess"
	_ "forward/internal/handler/vmess"

	// Shadowsocks
	_ "forward/internal/connector/ss"
	_ "forward/internal/handler/ss"
)

const defaultConnectURL = "http://www.gstatic.com/generate_204"

var subscribeDownload = subscribe.Download

func Main() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, subOpts, err := parseArgs(os.Args[1:])
	logger := cfg.Logger
	if logger == nil {
		level := logging.LevelInfo
		if err != nil {
			level = logging.LevelError
		}
		logger = logging.New(logging.Options{Level: level})
	}
	registerXrayLogHandler(logger.Level(), logger, cfg.DebugVerbose)

	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		logger.Error("Parse args error: %v", err)
		return 2
	}

	if cfg.Logger == nil {
		cfg.Logger = logger
	}

	// 如果有订阅 URL 但没有监听配置，走纯订阅模式
	if len(subOpts.URLs) > 0 && len(cfg.Listeners) == 0 && len(cfg.Nodes) == 0 {
		return runSubscribe(ctx, subOpts, cfg, cfg.Logger)
	}

	// 设置全局订阅参数
	cfg.SubscribeFilter = subOpts.Filter
	cfg.SubscribeUpdate = subOpts.Update

	routers := newRouterCache()

	if err := initRouteStoreAndHotReload(ctx, &cfg); err != nil {
		cfg.Logger.Error("Failed to init route store: %v", err)
		return 2
	}

	if len(cfg.Nodes) > 0 {
		var wg sync.WaitGroup
		listenerCount := 0
		for _, node := range cfg.Nodes {
			listenerCount += len(node.Listeners)
		}
		errCh := make(chan error, listenerCount)

		for _, node := range cfg.Nodes {
			for _, listen := range node.Listeners {
				nodeCfg := buildNodeConfig(cfg, node, listen)
				wg.Add(1)
				go func(c config.Config) {
					defer wg.Done()
					if err := runOne(ctx, c, routers); err != nil {
						c.Logger.Error("listener %s failed: %v", c.Listen.Address(), err)
						errCh <- err
						stop()
					}
				}(nodeCfg)
			}
		}
		wg.Wait()
		close(errCh)
		if err := <-errCh; err != nil {
			return 1
		}
	} else if len(cfg.Listeners) > 0 {
		if err := runOne(ctx, cfg, routers); err != nil {
			cfg.Logger.Error("Error: %v", err)
			return 1
		}
	} else {
		cfg.Logger.Error("No listen configsured. Use -L, -C, or -R.")
		return 1
	}

	return 0
}

func buildNodeConfig(global config.Config, node config.NodeConfig, listen endpoint.Endpoint) config.Config {
	cfg := global
	cfg.NodeName = node.Name
	cfg.Listen = listen
	cfg.Insecure = node.Insecure || global.Insecure
	if node.Forward != nil {
		cfg.Forward = node.Forward
	}
	if len(node.ForwardChain) > 0 {
		cfg.ForwardChain = node.ForwardChain
	}
	if node.SubscribeURL != "" {
		cfg.SubscribeURL = node.SubscribeURL
	}
	if len(node.SubscribeURLs) > 0 {
		cfg.SubscribeURLs = node.SubscribeURLs
	}
	if node.SubscribeFilter != "" {
		cfg.SubscribeFilter = node.SubscribeFilter
	}
	if node.SubscribeUpdate > 0 {
		cfg.SubscribeUpdate = node.SubscribeUpdate
	}
	cfg.Listeners = []endpoint.Endpoint{listen}
	return cfg
}

func runOne(ctx context.Context, cfg config.Config, routers *routerCache) error {
	scheme := strings.ToLower(cfg.Listen.Scheme)

	switch {
	case isReverseClient(cfg):
		return runReverseClient(ctx, cfg)
	case isReverseServer(cfg):
		return runReverseServer(ctx, cfg)
	case isPortForward(cfg):
		return runPortForward(ctx, cfg, routers)
	case isProxyServer(scheme):
		return runProxyServer(ctx, cfg, routers)
	default:
		return fmt.Errorf("unsupported scheme: %s", cfg.Listen.Scheme)
	}
}

// validatorProvider is implemented by listeners that expose a protocol validator.
type validatorProvider interface {
	Validator() interface{}
}

// validatorSetter is implemented by handlers that accept a protocol validator.
type validatorSetter interface {
	SetValidator(v interface{})
}

// passValidatorToHandler wires the listener's validator into the handler,
// used for VLESS + Reality authentication.
func passValidatorToHandler(ln interface{}, h interface{}) {
	if vp, ok := ln.(validatorProvider); ok {
		if vs, ok := h.(validatorSetter); ok {
			vs.SetValidator(vp.Validator())
		}
	}
}

// buildTLSOption returns a listener.TLSConfigOption for the given scheme and
// transport combination, or nil when no TLS is needed.
func buildTLSOption(cfg config.Config, handlerScheme, listenerScheme string, transport transportKind) (listener.Option, error) {
	var nextProtos []string
	needTLS := true

	switch {
	case listenerScheme == "http3" || listenerScheme == "h3":
		nextProtos = []string{"h3"}
	case listenerScheme == "http2" || listenerScheme == "h2":
		nextProtos = []string{"h2"}
	case transport == transportTLS:
		if handlerScheme == "http" {
			nextProtos = []string{"h2", "http/1.1"}
		}
	case transport == transportDTLS:
		// no nextProtos needed
	default:
		needTLS = false
	}

	if !needTLS {
		return nil, nil
	}

	tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{NextProtos: nextProtos})
	if err != nil {
		return nil, err
	}
	return listener.TLSConfigOption(tlsCfg), nil
}

// subscribeUpdateLoop periodically re-fetches subscription nodes and hot-swaps
// them into the balancer. It exits when the BalancerRoute is closed.
func subscribeUpdateLoop(cfg config.Config, hops []endpoint.Endpoint, subscribeURLs []string, br *chain.BalancerRoute) {
	ticker := time.NewTicker(time.Duration(cfg.SubscribeUpdate) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-br.Done():
			return
		case <-ticker.C:
			if cfg.Logger != nil {
				cfg.Logger.Info("Auto-updating subscriptions from %s", describeSubscribeSources(subscribeURLs))
			}
			var newNodes []*chain.Node
			var newCandidates []chain.BalancerCandidate
			var updateErr error

			for retry := 1; retry <= 3; retry++ {
				newNodes, newCandidates, updateErr = fetchAndBuildSubCandidates(cfg, hops)
				if updateErr == nil {
					break
				}
				if cfg.Logger != nil {
					cfg.Logger.Warn("Failed to update subscriptions (attempt %d/3): %v", retry, updateErr)
				}
				if retry < 3 {
					time.Sleep(5 * time.Second)
				}
			}

			if updateErr != nil {
				if cfg.Logger != nil {
					cfg.Logger.Error("Subscription update failed after 3 retries, keeping existing nodes.")
				}
				continue
			}

			if cfg.Logger != nil {
				cfg.Logger.Info("Successfully updated subscriptions, loaded %d nodes.", len(newCandidates))
			}

			if len(hops) > 0 {
				br.UpdateCandidates(newCandidates)
			} else {
				cands := make([]chain.BalancerCandidate, 0, len(newNodes))
				for _, n := range newNodes {
					cands = append(cands, chain.BalancerCandidate{Node: n})
				}
				br.UpdateCandidates(cands)
			}
		}
	}
}
