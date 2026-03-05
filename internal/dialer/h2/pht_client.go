package h2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"forward/base/logging"
	phtshared "forward/base/transport/h2"
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

	tokenOnce sync.Once
	tokenMu   sync.Mutex
	tokenPool chan string
	refilling atomic.Bool
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

	token, err := c.getToken(ctx, addr)
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

func (c *phtClient) getToken(ctx context.Context, addr string) (string, error) {
	c.tokenOnce.Do(func() {
		c.tokenPool = make(chan string, 4)
	})

	select {
	case token := <-c.tokenPool:
		c.prefetchTokens(addr)
		return token, nil
	default:
	}

	token, err := c.authorize(ctx, addr)
	if err != nil {
		return "", err
	}
	c.prefetchTokens(addr)
	return token, nil
}

func (c *phtClient) prefetchTokens(addr string) {
	c.tokenOnce.Do(func() {
		c.tokenPool = make(chan string, 4)
	})
	if c.tokenPool == nil || len(c.tokenPool) >= cap(c.tokenPool) {
		return
	}
	if !c.refilling.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer c.refilling.Store(false)
		c.tokenMu.Lock()
		defer c.tokenMu.Unlock()

		for len(c.tokenPool) < cap(c.tokenPool) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			token, err := c.authorize(ctx, addr)
			cancel()
			if err != nil {
				return
			}
			select {
			case c.tokenPool <- token:
			default:
				return
			}
		}
	}()
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
