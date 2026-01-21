package tests

import (
	"net/url"
	"testing"

	"forward/base/utils/crypto"
)

func TestProxyVlessReality(t *testing.T) {
	backendAddr, backendStop := startTCPEchoServer(t)
	defer backendStop()

	uuid := crypto.GenerateUUID()
	if uuid == "" {
		uuid = "11111111-1111-1111-1111-111111111111"
	}

	priv, pub, err := crypto.GenerateX25519Keys()
	if err != nil {
		t.Fatalf("generate reality keys: %v", err)
	}
	sid := crypto.GenerateShortID(4)

	serverQuery := url.Values{
		"key":  []string{priv},
		"sid":  []string{sid},
		"sni":  []string{"example.com"},
		"dest": []string{"example.com:443"},
	}
	serverEP, stop := startProxyServer(t, "vless+reality", url.User(uuid), serverQuery)
	defer stop()

	clientQuery := url.Values{
		"pbk":        []string{pub},
		"sid":        []string{sid},
		"sni":        []string{"example.com"},
		"security":   []string{"reality"},
		"type":       []string{"tcp"},
		"encryption": []string{"none"},
		"flow":       []string{"xtls-rprx-vision"},
	}
	clientEP := buildEndpoint(t, "reality", "127.0.0.1", serverEP.Port, url.User(uuid), clientQuery)

	route := buildRoute(t, clientEP)
	conn := dialWithRetry(t, route, "tcp", backendAddr)
	defer conn.Close()

	assertEcho(t, conn, []byte("reality-proxy"))
}
