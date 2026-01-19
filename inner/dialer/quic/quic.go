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

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"forward/inner/config"
	ctls "forward/inner/config/tls"
	"forward/inner/dialer"
)

type Dialer struct {
	target     string
	rt         *http3.Transport
	timeout    time.Duration
	authHeader string
	base       dialer.PacketDialer
	baseErr    error
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

func (d *Dialer) SetBase(base dialer.Dialer) {
	if base == nil {
		return
	}
	packetDialer, ok := base.(dialer.PacketDialer)
	if !ok {
		d.baseErr = fmt.Errorf("quic forward requires UDP-capable base")
		return
	}
	d.base = packetDialer
	d.rt.Dial = d.dialWithBase
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(strings.ToLower(network), "tcp") {
		return nil, fmt.Errorf("quic forward supports tcp only")
	}
	if d.baseErr != nil {
		return nil, d.baseErr
	}

	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		timeout := d.timeout
		if timeout <= 0 {
			timeout = config.DefaultDialTimeout
		}
		ctx, cancel = context.WithTimeout(ctx, timeout)
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

func (d *Dialer) dialWithBase(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	pc, err := d.base.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("quic forward udp init failed: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("quic forward resolve addr failed: %w", err)
	}

	conn, err := quic.Dial(ctx, pc, udpAddr, tlsCfg, cfg)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}

	go func() {
		<-conn.Context().Done()
		_ = pc.Close()
	}()

	return conn, nil
}
