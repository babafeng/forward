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

	"golang.org/x/net/http2"

	"forward/internal/connector"
	"forward/internal/handler/udptun"
	"forward/internal/metadata"
	"forward/internal/registry"
)

func init() {
	registry.ConnectorRegistry().Register("http", NewConnector)
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
	network = strings.ToLower(strings.TrimSpace(network))
	switch {
	case strings.HasPrefix(network, "tcp"):
	case strings.HasPrefix(network, "udp"):
	default:
		return nil, fmt.Errorf("http connector supports tcp/udp only")
	}

	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if state.NegotiatedProtocol == "h2" {
			t := &http2.Transport{}
			cc, err := t.NewClientConn(tlsConn)
			if err != nil {
				return nil, err
			}
			return c.dialH2(ctx, cc, network, address)
		}
	}

	return c.dialHTTP1(ctx, conn, network, address)
}

func (c *Connector) dialHTTP1(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error) {
	if deadline := deadlineFromContext(ctx, c.timeout); !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address)
	if isUDP(network) {
		req += "X-Forward-Protocol: udp\r\n"
	}
	if c.authVal != "" {
		req += fmt.Sprintf("Proxy-Authorization: %s\r\n", c.authVal)
	}
	req += "\r\n"

	if _, err := io.WriteString(conn, req); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := stdhttp.ReadResponse(br, &stdhttp.Request{Method: stdhttp.MethodConnect})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != stdhttp.StatusOK {
		return nil, fmt.Errorf("http proxy connect failed: %s", resp.Status)
	}

	_ = conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		conn = &readWriteConn{Conn: conn, r: br}
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

func (c *Connector) dialH2(ctx context.Context, cc *http2.ClientConn, network, address string) (net.Conn, error) {
	pr, pw := io.Pipe()
	req, err := stdhttp.NewRequestWithContext(ctx, "CONNECT", "//"+address, pr)
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
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != stdhttp.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("http2 proxy connect failed: %s", resp.Status)
	}

	conn := &h2Conn{
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

type h2Conn struct {
	r     io.Reader
	w     io.WriteCloser
	close func() error
}

func (c *h2Conn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *h2Conn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *h2Conn) Close() error                { return c.close() }
func (c *h2Conn) LocalAddr() net.Addr         { return nil }
func (c *h2Conn) RemoteAddr() net.Addr        { return nil }
func (c *h2Conn) SetDeadline(time.Time) error { return nil }
func (c *h2Conn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *h2Conn) SetWriteDeadline(time.Time) error {
	return nil
}

type readWriteConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readWriteConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func deadlineFromContext(ctx context.Context, fallback time.Duration) time.Time {
	if ctx == nil {
		return time.Time{}
	}
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	if fallback > 0 {
		return time.Now().Add(fallback)
	}
	return time.Time{}
}

func isUDP(network string) bool {
	return strings.HasPrefix(network, "udp")
}
