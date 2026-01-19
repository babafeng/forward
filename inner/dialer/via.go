package dialer

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type ViaDialer interface {
	DialContextVia(ctx context.Context, network, address, via string) (net.Conn, error)
}

func DialContextVia(ctx context.Context, d Dialer, network, address, via string) (net.Conn, error) {
	if d == nil {
		return nil, fmt.Errorf("dialer not initialized")
	}
	via = strings.ToUpper(strings.TrimSpace(via))
	if via == "" || via == "DIRECT" {
		return d.DialContext(ctx, network, address)
	}
	if via == "REJECT" {
		return nil, fmt.Errorf("route rejected")
	}
	if vd, ok := d.(ViaDialer); ok {
		return vd.DialContextVia(ctx, network, address, via)
	}
	return nil, fmt.Errorf("dialer does not support route via %s", via)
}
