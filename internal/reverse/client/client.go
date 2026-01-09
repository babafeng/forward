package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	quic "github.com/quic-go/quic-go"

	"forward/internal/config"
	ctls "forward/internal/config/tls"
	"forward/internal/dialer"
	"forward/internal/endpoint"
	inet "forward/internal/io/net"
	"forward/internal/logging"
	rproto "forward/internal/reverse/proto"

	"forward/internal/structs"
)

type Runner interface {
	Run(ctx context.Context) error
}

type Client struct {
	cfg        config.Config
	log        *logging.Logger
	serverDial dialer.Dialer
}

func NewRunner(cfg config.Config) (Runner, error) {
	d, err := dialer.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:        cfg,
		log:        cfg.Logger,
		serverDial: d,
	}, nil
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
	if c.cfg.Listen.Scheme == "udp" {
		network = "udp"
	}

	backoff := time.Second * 2
	for ctx.Err() == nil {
		start := time.Now()
		if err := c.connectOnce(ctx, network, host, port, target); err != nil && ctx.Err() == nil {
			if time.Since(start) > 5*time.Second {
				backoff = time.Second * 2
			}
			c.log.Error("Reverse client error: %v", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}
	return ctx.Err()
}

func (c *Client) connectOnce(ctx context.Context, network, bindHost string, bindPort int, target string) error {
	if c.cfg.Forward == nil {
		return fmt.Errorf("reverse client: forward endpoint is required")
	}
	forward := *c.cfg.Forward

	conn, err := c.dialServer(ctx, forward)
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}
	c.log.Info("Reverse client connected to %s", forward.Address())

	user, pass, _ := forward.UserPass()

	isUDP := (network == "udp")
	if err := rproto.Socks5ClientBind(conn, user, pass, bindHost, bindPort, isUDP); err != nil {
		conn.Close()
		return fmt.Errorf("socks5 bind: %w", err)
	}

	conf := yamux.DefaultConfig()
	conf.KeepAliveInterval = 10 * time.Second
	conf.LogOutput = nil // Clear default LogOutput to allow setting Logger
	conf.Logger = log.New(c.log.Writer(logging.LevelDebug), "[yamux] ", 0)

	session, err := yamux.Server(conn, conf)
	if err != nil {
		conn.Close()
		return fmt.Errorf("yamux server: %w", err)
	}
	defer session.Close()

	c.log.Info("Reverse client tunnel ready: remote %s exposes %s (%s)", forward.Address(), net.JoinHostPort(bindHost, fmt.Sprintf("%d", bindPort)), network)

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			session.Close()
			conn.Close()
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

	localDialer := dialer.NewDirect(c.cfg)

	c.log.Debug("Reverse %s Dialing upstream %s for client %s", network, target, src)
	out, err := localDialer.DialContext(ctx, network, target)
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

func (c *Client) dialServer(ctx context.Context, ep endpoint.Endpoint) (net.Conn, error) {
	switch ep.Scheme {
	case "tls", "https":
		tlsCfg, err := ctls.ClientConfig(ep, c.cfg.Insecure, ctls.ClientOptions{
			NextProtos: []string{"h2", "http/1.1"},
		})
		if err != nil {
			return nil, err
		}

		baseDial := dialer.NewNetDialer(c.cfg)
		return tls.DialWithDialer(baseDial, "tcp", ep.Address(), tlsCfg)
	case "tcp":
		return c.serverDial.DialContext(ctx, "tcp", ep.Address())
	case "quic", "http3":
		tlsCfg, err := ctls.ClientConfig(ep, c.cfg.Insecure, ctls.ClientOptions{
			NextProtos: []string{"h3"},
		})
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithTimeout(ctx, c.cfg.DialTimeout)

		qconn, err := quic.DialAddr(ctx, ep.Address(), tlsCfg, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		stream, err := qconn.OpenStreamSync(ctx)
		if err != nil {
			cancel()
			_ = qconn.CloseWithError(0, "")
			return nil, err
		}
		return &structs.QuicStreamConn{
			Stream:    stream,
			Local:     qconn.LocalAddr(),
			Remote:    qconn.RemoteAddr(),
			Closer:    qconn,
			CloseOnce: &sync.Once{},
			Cancel:    cancel,
		}, nil
	default:
		return nil, fmt.Errorf("reverse client: unsupported forward scheme %s", ep.Scheme)
	}
}
