package vless

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	_ "github.com/xtls/xray-core/transport/internet/tcp"

	"forward/internal/config"
	"forward/internal/dialer"
	inet "forward/internal/io/net"
	"forward/internal/listener"
	"forward/internal/logging"
	"forward/internal/protocol/vless"
	"forward/internal/utils/crypto"
)

func init() {
	listener.Register("vless", New)
	listener.Register("vless+reality", New)
}

type Listener struct {
	addr           string
	listener       internet.Listener
	dialer         dialer.Dialer
	uuid           vless.UUID
	log            *logging.Logger
	streamSettings *internet.MemoryStreamConfig
	xaddr          xnet.Address
	xport          xnet.Port

	// URL info
	url       string
	base64URL string
}

func New(cfg config.Config, d dialer.Dialer) (listener.Runner, error) {
	listen := cfg.Listen
	user := listen.User
	username := user.Username()
	if username == "" {
		return nil, fmt.Errorf("vless requires uuid in user field")
	}

	uuid, err := vless.ParseUUID(username)
	if err != nil {
		return nil, fmt.Errorf("invalid vless uuid: %w", err)
	}

	q := listen.Query
	security := "none"
	if strings.Contains(listen.Scheme, "reality") {
		security = "reality"
	}

	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	// conf.TransportProtocol(network) is not correct?
	// It's defined as type TransportProtocol string in conf.
	// So conversion should work if I use config import correctly?
	// Wait, compilation error "invalid composite literal type conf.TransportProtocol"
	// Ah, I was using &conf.TransportProtocol{Name: ...} which assumes struct.
	// If it is string: &networkStr (casted).

	// Let's use string variable and cast it to *conf.TransportProtocol
	// No, conf.TransportProtocol is string. *conf.TransportProtocol is *string.
	// Network field is *TransportProtocol.

	tp := conf.TransportProtocol(network)
	streamConf := &conf.StreamConfig{
		Network:  &tp,
		Security: security,
	}

	var pbk, sid, sni, flow string

	if security == "reality" {
		dest := q.Get("dest")
		if dest == "" {
			dest = "www.microsoft.com:443"
		}
		sni = q.Get("sni")
		if sni == "" {
			sni = "www.microsoft.com"
		}
		serverNames := []string{sni}

		privateKey := q.Get("key")
		if privateKey == "" {
			// Generate ephemeral key for ease of use
			priv, pub, err := crypto.GenerateX25519Keys()
			if err != nil {
				return nil, fmt.Errorf("failed to generate reality keys: %w", err)
			}
			privateKey = priv
			pbk = pub
		} else {
			// Derive public key
			pk, err := crypto.GetPublicKey(privateKey)
			if err != nil {
				return nil, fmt.Errorf("invalid private key: %w", err)
			}
			pbk = pk
		}

		shortIds := strings.Split(q.Get("sid"), ",")
		if len(shortIds) == 0 || shortIds[0] == "" {
			shortIds = []string{"abcd1234"}
		}
		sid = shortIds[0]

		flow = q.Get("flow")
		if flow == "" {
			flow = "xtls-rprx-vision"
		}

		streamConf.REALITYSettings = &conf.REALITYConfig{
			Show:        false,
			Dest:        json.RawMessage(fmt.Sprintf(`"%s"`, dest)),
			Xver:        0,
			ServerNames: serverNames,
			PrivateKey:  privateKey,
			ShortIds:    shortIds,
		}
	}

	pbStreamSettings, err := streamConf.Build()
	if err != nil {
		return nil, fmt.Errorf("build stream config failed: %w", err)
	}

	memStreamSettings, err := internet.ToMemoryStreamConfig(pbStreamSettings)
	if err != nil {
		return nil, fmt.Errorf("convert stream config failed: %w", err)
	}

	// Host/Port
	hostStr := listen.Host
	if hostStr == "" {
		hostStr = "0.0.0.0"
	}
	port := listen.Port

	// Generate URL
	var shadowrocketURL string
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

		shadowrocketURL = fmt.Sprintf("vless://%s@%s:%d?%s#VLESS-Reality",
			username, hostStr, port, params.Encode())
	}

	return &Listener{
		addr:           listen.Address(),
		dialer:         d,
		uuid:           uuid,
		log:            cfg.Logger,
		streamSettings: memStreamSettings,
		xaddr:          xnet.ParseAddress(hostStr),
		xport:          xnet.Port(port),
		url:            shadowrocketURL,
		base64URL:      base64.StdEncoding.EncodeToString([]byte(shadowrocketURL)),
	}, nil
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
		l.log.Info("Base64 URL: %s", l.base64URL)
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
