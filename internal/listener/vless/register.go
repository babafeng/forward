package vless

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"forward/internal/config"
	"forward/internal/dialer"
	"forward/internal/listener"
	"forward/internal/protocol/vless"
	"forward/internal/utils/crypto"
	"net/url"
	"strings"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"

	xnet "github.com/xtls/xray-core/common/net"
)

func init() {
	listener.Register("vless", newRunner)
	listener.Register("vless+reality", newRunner)
}

func newRunner(cfg config.Config, d dialer.Dialer) (listener.Runner, error) {
	listen := cfg.Listen
	user := listen.User
	username := user.Username()
	if username == "" {
		username = crypto.GenerateUUID()
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

	tp := conf.TransportProtocol(network)
	streamConf := &conf.StreamConfig{
		Network:  &tp,
		Security: security,
	}

	var pbk, sid, sni, flow string

	if security == "reality" {
		dest := q.Get("dest")
		if dest == "" {
			dest = "swscan.apple.com:443"
		}
		sni = q.Get("sni")
		if sni == "" {
			sni = "swscan.apple.com"
		}
		serverNames := []string{sni}

		privateKey := q.Get("key")
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

		shortIds := strings.Split(q.Get("sid"), ",")
		if len(shortIds) == 0 || shortIds[0] == "" {
			shortIds = []string{crypto.GenerateShortID(4)}
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

	hostStr := listen.Host
	if hostStr == "" {
		hostStr = "0.0.0.0"
	}
	port := listen.Port

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
