package quic

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"

	"forward/internal/config"
)

type Dialer struct {
	target     string
	rt         *http3.Transport
	timeout    time.Duration
	authHeader string
}

func New(cfg config.Config) (*Dialer, error) {
	proxyEp := cfg.Proxy
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.Insecure, //nolint:gosec
		ServerName:         proxyEp.Host,
		NextProtos:         []string{"h3"},
	}
	if sni := strings.TrimSpace(proxyEp.Query.Get("sni")); sni != "" {
		tlsCfg.ServerName = sni
	}

	rt := &http3.Transport{
		TLSClientConfig: tlsCfg,
	}

	var authHeader string
	if user, pass, ok := proxyEp.UserPass(); ok {
		creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		authHeader = "Basic " + creds
	}

	return &Dialer{
		target:     proxyEp.Address(),
		rt:         rt,
		timeout:    cfg.DialTimeout,
		authHeader: authHeader,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(strings.ToLower(network), "tcp") {
		return nil, fmt.Errorf("quic proxy supports tcp only")
	}

	proxyURL := fmt.Sprintf("https://%s", d.target)

	pr, pw := io.Pipe()

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, proxyURL, nil)
	if err != nil {
		return nil, err
	}
	req.Body = pr

	req.Host = address

	if d.authHeader != "" {
		req.Header.Set("Proxy-Authorization", d.authHeader)
	}

	resp, err := d.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("proxy connect failed: %s", resp.Status)
	}

	return &rwcConn{
		ReadWriteCloser: &combinedRWC{
			r: resp.Body,
			w: pw,
		},
	}, nil
}
