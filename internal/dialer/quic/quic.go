package quic

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"

	"forward/internal/config"
	ctls "forward/internal/config/tls"
)

type Dialer struct {
	target     string
	rt         *http3.Transport
	timeout    time.Duration
	authHeader string
}

func New(cfg config.Config) (*Dialer, error) {
	forward := cfg.Forward
	tlsCfg, err := ctls.ClientConfig(*forward, cfg.Insecure, ctls.ClientOptions{
		ServerName: forward.Host,
		NextProtos: []string{"h3"},
	})
	if err != nil {
		return nil, err
	}

	rt := &http3.Transport{
		TLSClientConfig: tlsCfg,
	}

	var authHeader string
	if user, pass, ok := forward.UserPass(); ok {
		creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		authHeader = "Basic " + creds
	}

	return &Dialer{
		target:     forward.Address(),
		rt:         rt,
		timeout:    cfg.DialTimeout,
		authHeader: authHeader,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(strings.ToLower(network), "tcp") {
		return nil, fmt.Errorf("quic forward supports tcp only")
	}

	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, d.timeout)
	}

	forwardURL := fmt.Sprintf("https://%s", d.target)

	pr, pw := io.Pipe()

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, forwardURL, nil)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, err
	}
	req.Body = pr

	req.Host = address

	if d.authHeader != "" {
		req.Header.Set("Proxy-Authorization", d.authHeader)
	}

	resp, err := d.rt.RoundTrip(req)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if cancel != nil {
			cancel()
		}
		return nil, fmt.Errorf("forward connect failed: %s", resp.Status)
	}

	return &RWCConn{
		ReadWriteCloser: &combinedRWC{
			r: resp.Body,
			w: pw,
		},
		cancel: cancel,
	}, nil
}
