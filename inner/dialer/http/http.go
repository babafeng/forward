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
	"sync"
	"time"

	"golang.org/x/net/http2"

	"forward/inner/config"
	ctls "forward/inner/config/tls"
	"forward/inner/dialer"
)

type Dialer struct {
	forward string
	useTLS  bool
	timeout time.Duration

	authVal   string
	tlsConfig *tls.Config
	base      dialer.Dialer

	h2Mu     sync.Mutex
	h2Client *http2.ClientConn
}

func New(cfg config.Config) (dialer.Dialer, error) {
	forward := cfg.Forward
	useTLS := strings.EqualFold(forward.Scheme, "https")

	var tlsCfg *tls.Config
	if useTLS {
		tc, err := ctls.ClientConfig(*forward, cfg.Insecure, ctls.ClientOptions{})
		if err != nil {
			return nil, fmt.Errorf("http dialer tls config: %w", err)
		}
		tlsCfg = tc
	}

	var authVal string
	if user, pass, ok := forward.UserPass(); ok {
		creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		authVal = "Basic " + creds
	}

	return &Dialer{
		forward:   forward.Address(),
		useTLS:    useTLS,
		timeout:   cfg.DialTimeout,
		authVal:   authVal,
		tlsConfig: tlsCfg,
		base:      dialer.NewDirect(cfg),
	}, nil
}

func (d *Dialer) SetBase(base dialer.Dialer) {
	if base == nil {
		return
	}
	d.h2Mu.Lock()
	d.h2Client = nil
	d.h2Mu.Unlock()
	d.base = base
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("http forward supports tcp only")
	}

	// Try existing H2 connection
	d.h2Mu.Lock()
	h2Client := d.h2Client
	d.h2Mu.Unlock()

	if h2Client != nil {
		conn, err := d.dialH2(ctx, h2Client, address)
		if err == nil {
			return conn, nil
		}
		// H2 failed (connection closed/broken), clear and retry dial
		d.h2Mu.Lock()
		if d.h2Client == h2Client {
			d.h2Client = nil
		}
		d.h2Mu.Unlock()
	}

	var base net.Conn
	var err error

	// Use unified NetDialer from config
	base, err = d.base.DialContext(ctx, "tcp", d.forward)
	if err != nil {
		return nil, err
	}

	if d.useTLS {
		// ALPN: Prefer h2, support http/1.1
		tlsCfg := d.tlsConfig.Clone()
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		tlsConn := tls.Client(base, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = base.Close()
			return nil, err
		}
		base = tlsConn

		state := tlsConn.ConnectionState()
		if state.NegotiatedProtocol == "h2" {
			t := &http2.Transport{}
			cc, err := t.NewClientConn(base)
			if err != nil {
				_ = base.Close()
				return nil, fmt.Errorf("failed to create http2 client conn: %w", err)
			}

			d.h2Mu.Lock()
			d.h2Client = cc
			d.h2Mu.Unlock()

			return d.dialH2(ctx, cc, address)
		}
	}

	// HTTP/1.1 Fallback
	if deadline, ok := ctx.Deadline(); ok {
		_ = base.SetDeadline(deadline)
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address)
	if d.authVal != "" {
		req += fmt.Sprintf("Proxy-Authorization: %s\r\n", d.authVal)
	}
	req += "\r\n"

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

func (d *Dialer) dialH2(ctx context.Context, cc *http2.ClientConn, address string) (net.Conn, error) {
	pr, pw := io.Pipe()
	req, err := stdhttp.NewRequest("CONNECT", "//"+address, pr)
	if err != nil {
		return nil, err
	}
	req.Host = address
	if d.authVal != "" {
		req.Header.Set("Proxy-Authorization", d.authVal)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != stdhttp.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("http2 proxy connect failed: %s", resp.Status)
	}

	return &h2Conn{
		r: resp.Body,
		w: pw,
		close: func() error {
			_ = resp.Body.Close()
			return pw.Close()
		},
		local:  nil,
		remote: nil,
	}, nil
}

type h2Conn struct {
	r     io.Reader
	w     io.WriteCloser
	close func() error

	local  net.Addr
	remote net.Addr
}

func (c *h2Conn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *h2Conn) Write(b []byte) (int, error) {
	return c.w.Write(b)
}

func (c *h2Conn) Close() error {
	return c.close()
}

func (c *h2Conn) LocalAddr() net.Addr {
	return c.local
}

func (c *h2Conn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *h2Conn) SetDeadline(t time.Time) error {
	return nil
}

func (c *h2Conn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *h2Conn) SetWriteDeadline(t time.Time) error {
	return nil
}
