package vless

import (
	"context"
	"fmt"
	"net"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	_ "github.com/xtls/xray-core/transport/internet/tcp"

	"forward/internal/dialer"
	inet "forward/internal/io/net"
	"forward/internal/logging"
	"forward/internal/protocol/vless"
)

type Listener struct {
	addr           string
	listener       internet.Listener
	dialer         dialer.Dialer
	uuid           vless.UUID
	log            *logging.Logger
	streamSettings *internet.MemoryStreamConfig
	xaddr          xnet.Address
	xport          xnet.Port

	url       string
	base64URL string
}

func (l *Listener) Run(ctx context.Context) error {
	ls, err := internet.ListenTCP(ctx, l.xaddr, l.xport, l.streamSettings, func(conn stat.Connection) {
		go l.handleConn(conn)
	})
	if err != nil {
		return fmt.Errorf("listen reality failed: %w", err)
	}
	l.listener = ls
	defer ls.Close()

	l.log.Info("VLESS Reality listening on %s", l.addr)
	if l.url != "" {
		l.log.Info("Shadowrocket URL: %s", l.url)
		l.log.Info("Replace 0.0.0.0 with your real IP in Shadowrocket URL")
	}

	<-ctx.Done()
	return nil
}

func (l *Listener) handleConn(conn net.Conn) {
	defer conn.Close()

	req, err := vless.ReadRequest(conn)
	if err != nil {
		l.log.Debug("Read VLESS request failed: %v", err)
		return
	}

	if req.UUID != l.uuid {
		l.log.Debug("Invalid UUID from %s", conn.RemoteAddr())
		return
	}

	l.log.Info("VLESS connect %s -> %s", conn.RemoteAddr(), req.Address)

	targetConn, err := l.dialer.DialContext(context.Background(), req.Network, req.Address)
	if err != nil {
		l.log.Error("Dial target %s failed: %v", req.Address, err)
		return
	}
	defer targetConn.Close()

	if err := vless.WriteResponse(conn, vless.Version, nil); err != nil {
		return
	}

	inet.Bidirectional(context.Background(), conn, targetConn)
}
