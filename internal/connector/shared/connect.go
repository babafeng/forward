package shared

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"golang.org/x/net/http2"

	"forward/internal/handler/udptun"
)

func DialHTTP2(ctx context.Context, cc *http2.ClientConn, network, address, authVal, errorPrefix string) (net.Conn, error) {
	pr, pw := io.Pipe()
	req, err := NewConnectRequest(ctx, "//"+address, pr, address, network, authVal)
	if err != nil {
		return nil, err
	}

	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	return ConnFromConnectResponse(resp, pw, network, address, errorPrefix)
}

func DialHTTPClient(ctx context.Context, client *http.Client, url, network, address, authVal, errorPrefix string) (net.Conn, error) {
	pr, pw := io.Pipe()
	req, err := NewConnectRequest(ctx, url, pr, address, network, authVal)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return ConnFromConnectResponse(resp, pw, network, address, errorPrefix)
}

func NewConnectRequest(ctx context.Context, url string, body io.Reader, host, network, authVal string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, url, body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = -1
	req.Host = host
	if IsUDP(network) {
		req.Header.Set("X-Forward-Protocol", "udp")
	}
	if authVal != "" {
		req.Header.Set("Proxy-Authorization", authVal)
	}
	return req, nil
}

func ConnFromConnectResponse(resp *http.Response, pw *io.PipeWriter, network, address, errorPrefix string) (net.Conn, error) {
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s proxy connect failed: %s", errorPrefix, resp.Status)
	}

	conn := &H2Conn{
		R: resp.Body,
		W: pw,
		CloseFunc: func() error {
			_ = resp.Body.Close()
			return pw.Close()
		},
	}
	if IsUDP(network) {
		udpAddr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, err
		}
		return udptun.ClientConn(conn, udpAddr), nil
	}
	return conn, nil
}
