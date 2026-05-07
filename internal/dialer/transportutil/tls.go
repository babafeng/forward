package transportutil

import (
	"crypto/tls"
	"net"
	"strings"
)

func HostFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.Trim(addr, "[]")
	}
	return strings.Trim(host, "[]")
}

func CloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
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
