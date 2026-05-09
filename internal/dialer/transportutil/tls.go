package transportutil

import (
	"crypto/tls"
	"net"
	"strings"
)

// SharedClientSessionCache 是一个跨 dialer 复用的 TLS client session cache。
// 共享同一个 cache 才能让 session resumption 生效：多个连接之间可用同一张
// session ticket，避免每次都走完整 TLS 握手（省一个 RTT + 证书链验证）。
//
// 只在普通 tls.Config 上填充；REALITY/VLESS 使用 utls 的另一条栈，不受影响。
var SharedClientSessionCache = tls.NewLRUClientSessionCache(128)

func HostFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.Trim(addr, "[]")
	}
	return strings.Trim(host, "[]")
}

func CloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{ClientSessionCache: SharedClientSessionCache}
	}
	cloned := cfg.Clone()
	if cloned.ClientSessionCache == nil {
		cloned.ClientSessionCache = SharedClientSessionCache
	}
	return cloned
}

func EnsureNextProtos(cfg *tls.Config, protos []string) {
	if cfg == nil || len(protos) == 0 {
		return
	}
	existing := map[string]struct{}{}
	for _, p := range cfg.NextProtos {
		existing[p] = struct{}{}
	}
	for _, p := range protos {
		if _, ok := existing[p]; !ok {
			cfg.NextProtos = append(cfg.NextProtos, p)
		}
	}
}
