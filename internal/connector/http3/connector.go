package http3

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"time"

	"forward/internal/connector"
	"forward/internal/handler/udptun"
	"forward/internal/metadata"
	"forward/internal/registry"
)

type clientProvider interface {
	HTTPClient() *stdhttp.Client
}

func init() {
	registry.ConnectorRegistry().Register("http3", NewConnector)
	registry.ConnectorRegistry().Register("quic", NewConnector)
}

type Connector struct {
	authVal string
	timeout time.Duration
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	var authVal string
	if options.Auth != nil {
		user := options.Auth.Username()
		pass, _ := options.Auth.Password()
		if user != "" || pass != "" {
			creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
			authVal = "Basic " + creds
		}
	}

	return &Connector{
		authVal: authVal,
		timeout: options.Timeout,
	}
}

func (c *Connector) Init(_ metadata.Metadata) error {
	return nil
}

func (c *Connector) Connect(ctx context.Context, conn net.Conn, network, address string, _ ...connector.ConnectOption) (net.Conn, error) {
	clientConn, ok := conn.(clientProvider)
	if !ok {
		return nil, fmt.Errorf("http3 connector requires http3 dialer connection")
	}
	client := clientConn.HTTPClient()
	if client == nil {
		return nil, fmt.Errorf("http3 connector missing client")
	}

	switch {
	case isTCP(network):
	case isUDP(network):
	default:
		return nil, fmt.Errorf("http3 connector supports tcp/udp only")
	}

	proxyAddr := ""
	if ra := conn.RemoteAddr(); ra != nil {
		proxyAddr = ra.String()
	}
	if proxyAddr == "" {
		return nil, fmt.Errorf("http3 connector missing proxy address")
	}

	pr, pw := io.Pipe()
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodConnect, "https://"+proxyAddr, pr)
	if err != nil {
		return nil, err
	}
	req.Host = address
	if isUDP(network) {
		req.Header.Set("X-Forward-Protocol", "udp")
	}
	if c.authVal != "" {
		req.Header.Set("Proxy-Authorization", c.authVal)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != stdhttp.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("http3 proxy connect failed: %s", resp.Status)
	}

	conn = &h3Conn{
		r: resp.Body,
		w: pw,
		close: func() error {
			_ = resp.Body.Close()
			return pw.Close()
		},
	}

	if isUDP(network) {
		udpAddr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, err
		}
		return udptun.ClientConn(conn, udpAddr), nil
	}
	return conn, nil
}

type h3Conn struct {
	r     io.Reader
	w     io.WriteCloser
	close func() error
}

func (c *h3Conn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *h3Conn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *h3Conn) Close() error                { return c.close() }
func (c *h3Conn) LocalAddr() net.Addr         { return nil }
func (c *h3Conn) RemoteAddr() net.Addr        { return nil }
func (c *h3Conn) SetDeadline(time.Time) error { return nil }
func (c *h3Conn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *h3Conn) SetWriteDeadline(time.Time) error {
	return nil
}

func isUDP(network string) bool {
	return len(network) >= 3 && network[:3] == "udp"
}

func isTCP(network string) bool {
	return len(network) >= 3 && network[:3] == "tcp"
}
