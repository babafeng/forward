package shared

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"forward/internal/connector"
)

type Config struct {
	AuthVal string
	Timeout time.Duration
}

func NewConfig(opts ...connector.Option) Config {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return Config{
		AuthVal: BuildBasicAuth(options),
		Timeout: options.Timeout,
	}
}

// IsUDP 判断是否为 UDP 网络类型
func IsUDP(network string) bool {
	network = strings.ToLower(strings.TrimSpace(network))
	return strings.HasPrefix(network, "udp")
}

// IsTCP 判断是否为 TCP 网络类型
func IsTCP(network string) bool {
	network = strings.ToLower(strings.TrimSpace(network))
	return strings.HasPrefix(network, "tcp")
}

// DeadlineFromContext 从 ctx 或 fallback duration 计算 deadline
func DeadlineFromContext(ctx context.Context, fallback time.Duration) time.Time {
	if ctx == nil {
		return time.Time{}
	}
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	if fallback > 0 {
		return time.Now().Add(fallback)
	}
	return time.Time{}
}

// BuildBasicAuth 从 connector.Options 构建 Basic Auth 头值
func BuildBasicAuth(opts connector.Options) string {
	if opts.Auth != nil {
		user := opts.Auth.Username()
		pass, _ := opts.Auth.Password()
		if user != "" || pass != "" {
			creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
			return "Basic " + creds
		}
	}
	return ""
}
