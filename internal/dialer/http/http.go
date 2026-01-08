package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"time"

	"forward/internal/config"
	"forward/internal/dialer"
)

type Dialer struct {
	forward string
	useTLS  bool
	timeout time.Duration

	authHeader string
	tlsConfig  *tls.Config
}

func New(cfg config.Config) (dialer.Dialer, error) {
	forward := cfg.Forward
	useTLS := strings.EqualFold(forward.Scheme, "https")

	var tlsCfg *tls.Config
	if useTLS {
		tlsCfg = &tls.Config{
			InsecureSkipVerify: cfg.Insecure,
		}
		if forward.Host != "" {
			tlsCfg.ServerName = forward.Host
		}
	}

	var authHeader string
	if user, pass, ok := forward.UserPass(); ok {
		creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		authHeader = "Proxy-Authorization: Basic " + creds + "\r\n"
	}

	return &Dialer{
		forward:    forward.Address(),
		useTLS:     useTLS,
		timeout:    cfg.DialTimeout,
		authHeader: authHeader,
		tlsConfig:  tlsCfg,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("http forward supports tcp only")
	}

	var base net.Conn
	var err error

	var nd net.Dialer
	nd.Timeout = d.timeout
	nd.KeepAlive = 30 * time.Second

	if d.useTLS {
		// Use DialContext + HandshakeContext to support cancellation
		base, err = nd.DialContext(ctx, "tcp", d.forward)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(base, d.tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = base.Close()
			return nil, err
		}
		base = tlsConn
	} else {
		base, err = nd.DialContext(ctx, "tcp", d.forward)
	}
	if err != nil {
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = base.SetDeadline(deadline)
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", address, address, d.authHeader)
	if d.authHeader == "" {
		req = fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", address, address)
	}

	if _, err := io.WriteString(base, req); err != nil {
		_ = base.Close()
		return nil, err
	}

	br := bufio.NewReader(base)
	resp, err := stdhttp.ReadResponse(br, &stdhttp.Request{Method: stdhttp.MethodConnect})
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != stdhttp.StatusOK {
		_ = base.Close()
		return nil, fmt.Errorf("http proxy connect failed: %s", resp.Status)
	}

	_ = base.SetDeadline(time.Time{})
	return base, nil
}
