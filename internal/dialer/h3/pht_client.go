package h3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"forward/base/logging"
	phtshared "forward/base/transport/h3"
)

type phtClient struct {
	Host          string
	Client        *http.Client
	AuthorizePath string
	PushPath      string
	PullPath      string
	TLSEnabled    bool
	Logger        *logging.Logger
	Secret        string
}

func (c *phtClient) Dial(ctx context.Context, addr string) (net.Conn, error) {
	raddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		if c.Logger != nil {
			c.Logger.Error("pht: resolve %s: %v", addr, err)
		}
		return nil, err
	}

	if c.Host != "" {
		addr = net.JoinHostPort(c.Host, fmt.Sprintf("%d", raddr.Port))
	}

	token, err := c.authorize(ctx, addr)
	if err != nil {
		if c.Logger != nil {
			c.Logger.Error("pht: authorize: %v", err)
		}
		return nil, err
	}

	scheme := "http"
	if c.TLSEnabled {
		scheme = "https"
	}
	pushURL := fmt.Sprintf("%s://%s%s?token=%s", scheme, addr, c.PushPath, token)
	pullURL := fmt.Sprintf("%s://%s%s?token=%s", scheme, addr, c.PullPath, token)
	return phtshared.NewClientConn(c.Client, pushURL, pullURL, c.Secret, raddr, c.Logger), nil
}

func (c *phtClient) authorize(ctx context.Context, addr string) (string, error) {
	scheme := "http"
	if c.TLSEnabled {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, addr, c.AuthorizePath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if c.Secret != "" {
		req.Header.Set("X-PHT-Secret", c.Secret)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	token := strings.TrimSpace(string(data))
	token = strings.TrimPrefix(token, "token=")
	if token == "" {
		return "", errors.New("authorize failed")
	}
	return token, nil
}
