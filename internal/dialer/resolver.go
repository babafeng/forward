package dialer

import (
	"context"
	"net"
	"strings"
	"time"
)

func NewResolver(servers []string, timeout time.Duration) *net.Resolver {
	clean := make([]string, 0, len(servers))
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "53")
		}
		clean = append(clean, server)
	}
	if len(clean) == 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: timeout}
			var lastErr error
			for _, server := range clean {
				conn, err := dialer.DialContext(ctx, "udp", server)
				if err == nil {
					return conn, nil
				}
				lastErr = err

				conn, err = dialer.DialContext(ctx, "tcp", server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, net.UnknownNetworkError("no valid dns server found")
		},
	}
}
