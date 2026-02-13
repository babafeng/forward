// Package reality 提供 Reality TLS 传输层 Dialer
package reality

import (
	"context"
	"fmt"
	"net"
	"strings"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"

	"forward/internal/dialer"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.DialerRegistry().Register("reality", NewDialer)
}

type Dialer struct {
	proxyHost      string
	proxyPort      int
	streamSettings *internet.MemoryStreamConfig
	options        dialer.Options
}

// NewDialer 创建新的 Reality Dialer
func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &Dialer{
		options: options,
	}
}

func (d *Dialer) Init(md metadata.Metadata) error {
	if md == nil {
		return fmt.Errorf("reality dialer requires metadata")
	}

	// 解析服务器地址
	d.proxyHost = md.GetString(metadata.KeyHost)
	d.proxyPort = md.GetInt(metadata.KeyPort)
	if d.proxyHost == "" || d.proxyPort == 0 {
		return fmt.Errorf("reality dialer requires host and port")
	}

	// 构建 stream settings
	streamSettings, err := d.buildStreamSettings(md)
	if err != nil {
		return fmt.Errorf("build reality stream settings failed: %w", err)
	}
	d.streamSettings = streamSettings

	return nil
}

func (d *Dialer) buildStreamSettings(md metadata.Metadata) (*internet.MemoryStreamConfig, error) {
	security := md.GetString(metadata.KeySecurity)
	if security == "" {
		security = "reality"
	}

	network := md.GetString(metadata.KeyNetwork)
	if network == "" {
		network = "tcp"
	}

	tp := conf.TransportProtocol(network)
	streamConf := &conf.StreamConfig{
		Network:  &tp,
		Security: security,
	}

	fpOrDefault := func(fp string) string {
		if fp == "" {
			return "chrome"
		}
		return fp
	}

	switch security {
	case "reality":
		streamConf.REALITYSettings = &conf.REALITYConfig{
			Show:        false,
			Fingerprint: fpOrDefault(md.GetString(metadata.KeyFingerprint)),
			ServerName:  md.GetString(metadata.KeySNI),
			PublicKey:   md.GetString(metadata.KeyPublicKey),
			ShortId:     md.GetString(metadata.KeyShortID),
			SpiderX:     md.GetString(metadata.KeySpiderX),
		}
	case "tls":
		alpnStr := md.GetString(metadata.KeyALPN)
		var alpnList *conf.StringList
		if alpnStr != "" {
			alpn := strings.Split(alpnStr, ",")
			sl := conf.StringList(alpn)
			alpnList = &sl
		}
		streamConf.TLSSettings = &conf.TLSConfig{
			ServerName:    md.GetString(metadata.KeySNI),
			Fingerprint:   fpOrDefault(md.GetString(metadata.KeyFingerprint)),
			ALPN:          alpnList,
			AllowInsecure: md.GetBool(metadata.KeyInsecure),
		}
	}

	pbStreamSettings, err := streamConf.Build()
	if err != nil {
		return nil, err
	}

	return internet.ToMemoryStreamConfig(pbStreamSettings)
}

func (d *Dialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	// 对于 Reality Dialer，addr 参数被忽略，使用初始化时配置的服务器地址
	proxyDest := xnet.TCPDestination(xnet.ParseAddress(d.proxyHost), xnet.Port(d.proxyPort))

	conn, err := internet.Dial(ctx, proxyDest, d.streamSettings)
	if err != nil {
		return nil, fmt.Errorf("dial reality failed: %w", err)
	}

	return conn, nil
}

// Handshake 执行 Reality TLS 握手（适用于已有连接的情况）
// 注意：如果连接是通过 Dial 方法建立的，TLS 握手已完成，直接返回连接
func (d *Dialer) Handshake(ctx context.Context, conn net.Conn, opts ...dialer.HandshakeOption) (net.Conn, error) {
	if d.streamSettings == nil {
		// 如果没有初始化，说明是通过 Dial 建立的已完成握手的连接
		return conn, nil
	}

	// 检查连接是否已经是 TLS/Reality 连接
	// 如果是，直接返回，无需再次握手
	switch conn.(type) {
	case *tls.Conn, *tls.UConn:
		return conn, nil
	}

	// 检查是否是 xray reality 连接类型
	connType := fmt.Sprintf("%T", conn)
	if strings.Contains(connType, "reality") || strings.Contains(connType, "Reality") {
		return conn, nil
	}

	proxyDest := xnet.TCPDestination(xnet.ParseAddress(d.proxyHost), xnet.Port(d.proxyPort))

	// 检查是否是 TLS 配置
	if tlsConfig := tls.ConfigFromStreamSettings(d.streamSettings); tlsConfig != nil {
		tlsConf := tlsConfig.GetTLSConfig(tls.WithDestination(proxyDest))
		if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
			conn = tls.UClient(conn, tlsConf, fingerprint)
			if err := conn.(*tls.UConn).HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("tls handshake failed: %w", err)
			}
		} else {
			conn = tls.Client(conn, tlsConf)
			if err := conn.(*tls.Conn).HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("tls handshake failed: %w", err)
			}
		}
		return conn, nil
	}

	// 检查是否是 Reality 配置
	if realityConfig := reality.ConfigFromStreamSettings(d.streamSettings); realityConfig != nil {
		realityConn, err := reality.UClient(conn, realityConfig, ctx, proxyDest)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("reality handshake failed: %w", err)
		}
		return realityConn, nil
	}

	return conn, nil
}
