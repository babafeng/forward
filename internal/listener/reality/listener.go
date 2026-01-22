// Package reality 提供 Reality TLS 监听器
package reality

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	xuuid "github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/infra/conf"
	xvless "github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"

	pvless "forward/base/protocol/vless"
	"forward/base/utils/crypto"
	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
)

const (
	maxConnections    = 2048
	DefaultRealitySNI = "swscan.apple.com"
)

func init() {
	registry.ListenerRegistry().Register("reality", NewListener)
	registry.ListenerRegistry().Register("vless+reality", NewListener)
}

type Listener struct {
	addr           string
	host           string
	port           int
	xlistener      internet.Listener
	streamSettings *internet.MemoryStreamConfig
	validator      xvless.Validator
	connCh         chan net.Conn
	errCh          chan error
	closeCh        chan struct{}
	closeOnce      sync.Once
	clientURL      string

	options listener.Options
}

// NewListener 创建新的 Reality Listener
func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &Listener{
		options: options,
		connCh:  make(chan net.Conn, maxConnections),
		errCh:   make(chan error, 1),
		closeCh: make(chan struct{}),
	}
}

func (l *Listener) Init(md metadata.Metadata) error {
	if md == nil {
		return fmt.Errorf("reality listener requires metadata")
	}

	l.host = md.GetString(metadata.KeyHost)
	if l.host == "" {
		l.host = "0.0.0.0"
	}
	l.port = md.GetInt(metadata.KeyPort)
	if l.port == 0 {
		return fmt.Errorf("reality listener requires port")
	}
	l.addr = net.JoinHostPort(l.host, fmt.Sprintf("%d", l.port))

	// 构建 Reality 配置
	serverCfg, err := l.buildServerConfig(md)
	if err != nil {
		return fmt.Errorf("build reality server config failed: %w", err)
	}

	l.streamSettings = serverCfg.StreamSettings
	l.validator = serverCfg.Validator
	l.clientURL = serverCfg.ClientURL

	// 启动监听
	xaddr := xnet.ParseAddress(l.host)
	xport := xnet.Port(l.port)

	xl, err := internet.ListenTCP(l.options.Context, xaddr, xport, l.streamSettings, func(conn stat.Connection) {
		select {
		case l.connCh <- conn:
		case <-l.closeCh:
			_ = conn.Close()
		default:
			_ = conn.Close()
		}
	})
	if err != nil {
		return fmt.Errorf("listen reality failed: %w", err)
	}
	l.xlistener = xl

	return nil
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connCh:
		return conn, nil
	case err := <-l.errCh:
		return nil, err
	case <-l.closeCh:
		return nil, listener.ErrClosed
	}
}

func (l *Listener) Addr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP(l.host),
		Port: l.port,
	}
}

func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closeCh)
		if l.xlistener != nil {
			_ = l.xlistener.Close()
		}
	})
	return nil
}

// Validator 返回用户验证器
func (l *Listener) Validator() interface{} {
	return l.validator
}

// ClientURL 返回客户端配置 URL
func (l *Listener) ClientURL() string {
	return l.clientURL
}

// ServerConfig 保存服务器配置
type ServerConfig struct {
	StreamSettings *internet.MemoryStreamConfig
	Validator      xvless.Validator
	ClientURL      string
}

func (l *Listener) buildServerConfig(md metadata.Metadata) (*ServerConfig, error) {
	// 获取或生成 UUID
	uuidStr := md.GetString(metadata.KeyUUID)
	if uuidStr == "" {
		uuidStr = crypto.GenerateUUID()
	}

	uuid, err := pvless.ParseUUID(uuidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid vless uuid: %w", err)
	}

	parsedUUID, err := xuuid.ParseBytes(uuid[:])
	if err != nil {
		return nil, fmt.Errorf("invalid vless uuid: %w", err)
	}

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

	var pbk, sid, sni, flow string

	if security == "reality" {
		// Reality 配置
		dest := md.GetString("dest")
		if dest == "" {
			dest = fmt.Sprintf("%s:443", DefaultRealitySNI)
		}

		sni = md.GetString(metadata.KeySNI)
		if sni == "" {
			sni = DefaultRealitySNI
		}

		privateKey := md.GetString("privatekey")
		if privateKey == "" {
			priv, pub, err := crypto.GenerateX25519Keys()
			if err != nil {
				return nil, fmt.Errorf("failed to generate reality keys: %w", err)
			}
			privateKey = priv
			pbk = pub
		} else {
			pk, err := crypto.GetPublicKey(privateKey)
			if err != nil {
				return nil, fmt.Errorf("invalid private key: %w", err)
			}
			pbk = pk
		}

		shortIds := strings.Split(md.GetString(metadata.KeyShortID), ",")
		if len(shortIds) == 0 || shortIds[0] == "" {
			shortIds = []string{crypto.GenerateShortID(4)}
		}
		sid = shortIds[0]

		flow = md.GetString(metadata.KeyFlow)
		if flow == "" {
			flow = pvless.AddonFlowVision
		}

		streamConf.REALITYSettings = &conf.REALITYConfig{
			Show:        false,
			Dest:        json.RawMessage(fmt.Sprintf(`"%s"`, dest)),
			Xver:        0,
			ServerNames: []string{sni},
			PrivateKey:  privateKey,
			ShortIds:    shortIds,
		}
	}

	// 创建用户验证器
	memUser := &protocol.MemoryUser{
		Account: &xvless.MemoryAccount{
			ID: protocol.NewID(parsedUUID),
		},
	}
	if flow != "" {
		memUser.Account.(*xvless.MemoryAccount).Flow = flow
	}

	validator := &xvless.MemoryValidator{}
	if err := validator.Add(memUser); err != nil {
		return nil, fmt.Errorf("init vless user failed: %w", err)
	}

	// 构建 stream settings
	pbStreamSettings, err := streamConf.Build()
	if err != nil {
		return nil, fmt.Errorf("build stream config failed: %w", err)
	}

	memStreamSettings, err := internet.ToMemoryStreamConfig(pbStreamSettings)
	if err != nil {
		return nil, fmt.Errorf("convert stream config failed: %w", err)
	}

	// 生成客户端 URL
	var clientURL string
	if security == "reality" {
		params := url.Values{}
		params.Set("encryption", "none")
		params.Set("flow", flow)
		params.Set("security", "reality")
		params.Set("sni", sni)
		params.Set("fp", "chrome")
		params.Set("pbk", pbk)
		params.Set("sid", sid)
		params.Set("type", network)

		clientURL = fmt.Sprintf("vless://%s@%s:%d?%s#VLESS-Reality",
			uuidStr, l.host, l.port, params.Encode())
	}

	return &ServerConfig{
		StreamSettings: memStreamSettings,
		Validator:      validator,
		ClientURL:      clientURL,
	}, nil
}

// WithHandshakeTimeout 创建带超时的连接包装
type timeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *timeoutConn) Read(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Read(b)
}
