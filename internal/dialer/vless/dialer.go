package vless

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tcp"

	"forward/internal/config"
	"forward/internal/dialer"
	"forward/internal/protocol/vless"
)

func init() {
	dialer.Register("vless", New)
}

type Dialer struct {
	proxyDest      xnet.Destination
	uuid           vless.UUID
	streamSettings *internet.MemoryStreamConfig
}

func New(cfg config.Config) (dialer.Dialer, error) {
	ep := cfg.Forward
	if ep == nil {
		return nil, fmt.Errorf("vless dialer requires forward endpoint")
	}

	user := ep.User
	if user == nil {
		return nil, fmt.Errorf("vless uuid is required")
	}
	username := user.Username()
	if username == "" {
		return nil, fmt.Errorf("vless uuid is required")
	}

	uuid, err := vless.ParseUUID(username)
	if err != nil {
		return nil, fmt.Errorf("invalid vless uuid: %w", err)
	}

	host := ep.Host
	port := ep.Port
	proxyDest := xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port))

	q := ep.Query
	security := q.Get("security")
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}

	tp := conf.TransportProtocol(network)
	streamConf := &conf.StreamConfig{
		Network:  &tp,
		Security: security,
	}

	if security == "reality" {
		streamConf.REALITYSettings = &conf.REALITYConfig{
			Show:        false,
			Fingerprint: q.Get("fp"),
			ServerName:  q.Get("sni"),
			PublicKey:   q.Get("pbk"),
			ShortId:     q.Get("sid"),
			SpiderX:     q.Get("u"),
		}
	} else if security == "tls" {
		streamConf.TLSSettings = &conf.TLSConfig{
			ServerName:  q.Get("sni"),
			Fingerprint: q.Get("fp"),
		}
		if q.Get("insecure") == "true" || cfg.Insecure {
			streamConf.TLSSettings.Insecure = true
		}
	}

	pbStreamSettings, err := streamConf.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build stream settings: %w", err)
	}

	memStreamSettings, err := internet.ToMemoryStreamConfig(pbStreamSettings)
	if err != nil {
		return nil, fmt.Errorf("failed to convert stream settings: %w", err)
	}

	return &Dialer{
		proxyDest:      proxyDest,
		uuid:           uuid,
		streamSettings: memStreamSettings,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := internet.Dial(ctx, d.proxyDest, d.streamSettings)
	if err != nil {
		return nil, fmt.Errorf("dial proxy failed: %w", err)
	}

	targetNetwork := "tcp"
	if strings.HasPrefix(strings.ToLower(network), "udp") {
		targetNetwork = "udp"
	}

	if err := vless.ClientHandshake(conn, d.uuid, address, targetNetwork); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless handshake failed: %w", err)
	}

	respBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read vless response failed: %w", err)
	}

	if respBuf[0] != vless.Version {
		conn.Close()
		return nil, fmt.Errorf("vless response version mismatch: %d", respBuf[0])
	}

	addonLen := int(respBuf[1])
	if addonLen > 0 {
		addons := make([]byte, addonLen)
		if _, err := io.ReadFull(conn, addons); err != nil {
			conn.Close()
			return nil, fmt.Errorf("read vless addons failed: %w", err)
		}
	}

	return conn, nil
}
