package vless

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
	xuuid "github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/infra/conf"
	xvless "github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport/internet"

	"forward/internal/config"
	pvless "forward/internal/protocol/vless"
	"forward/internal/utils/crypto"
)

type ServerConfig struct {
	StreamSettings *internet.MemoryStreamConfig
	Validator      xvless.Validator
	Host           string
	Port           int
	Address        string
	URL            string
}

func BuildServerConfig(cfg config.Config) (*ServerConfig, error) {
	listen := cfg.Listen
	user := listen.User
	var username string
	if user != nil {
		username = user.Username()
	}
	if username == "" {
		username = crypto.GenerateUUID()
	}

	uuid, err := pvless.ParseUUID(username)
	if err != nil {
		return nil, fmt.Errorf("invalid vless uuid: %w", err)
	}

	parsedUUID, err := xuuid.ParseBytes(uuid[:])
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
			dest = fmt.Sprintf("%s:443", config.DefaultRealitySNI)
		}
		sni = q.Get("sni")
		if sni == "" {
			sni = config.DefaultRealitySNI
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
			flow = pvless.AddonFlowVision
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
	address := net.JoinHostPort(hostStr, fmt.Sprintf("%d", port))

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

	return &ServerConfig{
		StreamSettings: memStreamSettings,
		Validator:      validator,
		Host:           hostStr,
		Port:           port,
		Address:        address,
		URL:            shadowrocketURL,
	}, nil
}
