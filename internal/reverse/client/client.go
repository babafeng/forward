package client

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/yamux"

	"forward/base/endpoint"
	inet "forward/base/io/net"
	"forward/base/logging"
	"forward/internal/chain"
	"forward/internal/config"
	rev "forward/internal/reverse"
	rproto "forward/internal/reverse/proto"
)

type Runner interface {
	Run(ctx context.Context) error
}

type Client struct {
	cfg     config.Config
	log     *logging.Logger
	route   chain.Route
	forward endpoint.Endpoint
}

func New(cfg config.Config, route chain.Route, forward endpoint.Endpoint) Runner {
	return &Client{
		cfg:     cfg,
		log:     cfg.Logger,
		route:   route,
		forward: forward,
	}
}

func (c *Client) Run(ctx context.Context) error {
	target := c.cfg.Listen.FAddress
	if target == "" {
		return fmt.Errorf("reverse client: listen forward address is required")
	}
	host := c.cfg.Listen.Host
	if host == "" {
		host = "0.0.0.0"
	}
	port := c.cfg.Listen.Port

	network := "tcp"
	if c.cfg.Listen.Scheme == "rudp" {
		network = "udp"
	}

	backoff := config.DefaultInitialBackoff
	if backoff <= 0 {
		backoff = 2 * time.Second
	}
	maxBackoff := config.DefaultMaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 30 * time.Second
	}

	for ctx.Err() == nil {
		start := time.Now()
		if err := c.connectOnce(ctx, network, host, port, target); err != nil && ctx.Err() == nil {
			if time.Since(start) > 5*time.Second {
				backoff = config.DefaultInitialBackoff
				if backoff <= 0 {
					backoff = 2 * time.Second
				}
			}
			c.log.Error("Reverse client error: %v", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
	}
	return ctx.Err()
}

func (c *Client) connectOnce(ctx context.Context, network, bindHost string, bindPort int, target string) error {
	conn, err := c.dialServer(ctx)
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}
	c.log.Info("Reverse client connected to %s", c.forward.Address())

	user, pass, _ := c.forward.UserPass()
	isUDP := (network == "udp")
	if err := rproto.Socks5ClientBind(conn, user, pass, bindHost, bindPort, isUDP); err != nil {
		_ = conn.Close()
		return fmt.Errorf("socks5 bind: %w", err)
	}

	conf := rev.NewYamuxConfig(c.log)
	session, err := yamux.Server(conn, conf)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("yamux server: %w", err)
	}
	defer session.Close()

	c.log.Info("Reverse client tunnel ready: remote %s exposes %s (%s)", c.forward.Address(), net.JoinHostPort(bindHost, fmt.Sprintf("%d", bindPort)), network)

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	for {
		stream, err := session.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go c.handleStream(ctx, stream, network, target)
	}
}

func (c *Client) handleStream(ctx context.Context, stream net.Conn, network, target string) {
	defer stream.Close()

	src := stream.RemoteAddr().String()
	c.log.Info("Forward Reverse Client Received connection %s --> %s", src, target)
	c.log.Debug("Reverse %s Received connection from %s", network, src)

	dialTimeout := c.cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = config.DefaultDialTimeout
	}
	dialer := &net.Dialer{Timeout: dialTimeout}
	out, err := dialer.DialContext(ctx, network, target)
	if err != nil {
		c.log.Error("Reverse client dial local %s error: %v", target, err)
		return
	}
	defer out.Close()

	c.log.Debug("Reverse %s Connected to upstream %s --> %s", network, src, target)

	var bytes int64
	var dur time.Duration

	if network == "udp" {
		ps := inet.NewPacketStream(stream)
		bytes, dur, err = inet.Bidirectional(ctx, out, ps)
	} else {
		bytes, dur, err = inet.Bidirectional(ctx, stream, out)
	}

	if err != nil && ctx.Err() == nil {
		c.log.Error("Reverse client transfer error: %v", err)
	}
	c.log.Debug("Reverse %s Closed connection %s --> %s transferred %d bytes in %s", network, src, target, bytes, dur)
}

func (c *Client) dialServer(ctx context.Context) (net.Conn, error) {
	if c.route == nil {
		timeout := config.DefaultDialTimeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		d := &net.Dialer{Timeout: timeout}
		return d.DialContext(ctx, "tcp", c.forward.Address())
	}
	return c.route.Dial(ctx, "tcp", c.forward.Address())
}
