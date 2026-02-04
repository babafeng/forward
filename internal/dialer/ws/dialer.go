package ws

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"forward/internal/dialer"
	"forward/internal/metadata"
	"forward/internal/registry"

	"github.com/gorilla/websocket"
)

func init() {
	registry.DialerRegistry().Register("ws", NewDialer)
}

type Dialer struct {
	path     string
	host     string
	security string
	dialer   *websocket.Dialer
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	return &Dialer{
		path: "/",
		dialer: &websocket.Dialer{
			HandshakeTimeout: 10 * time.Second,
			NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, network, addr)
			},
		},
	}
}

func (d *Dialer) Init(md metadata.Metadata) error {
	if md == nil {
		return nil
	}
	if path := md.GetString(metadata.KeyPath); path != "" {
		d.path = path
	}
	if host := md.GetString(metadata.KeyHost); host != "" {
		d.host = host
	}
	if security := md.GetString(metadata.KeySecurity); security != "" {
		d.security = strings.ToLower(security)
	}
	if md.GetBool(metadata.KeyInsecure) {
		d.dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return nil
}

func (d *Dialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	scheme := "ws"
	if d.security == "tls" || d.security == "ssl" {
		scheme = "wss"
	}

	header := http.Header{}
	if d.host != "" {
		header.Set("Host", d.host)
	}

	u := url.URL{
		Scheme: scheme,
		Host:   addr,
		Path:   d.path,
	}

	c, _, err := d.dialer.DialContext(ctx, u.String(), header)
	if err != nil {
		return nil, fmt.Errorf("ws dial %s error: %w", u.String(), err)
	}
	return &wsConn{Conn: c.UnderlyingConn(), c: c}, nil
}

type wsConn struct {
	net.Conn
	c      *websocket.Conn
	reader io.Reader
}

func (w *wsConn) Read(b []byte) (int, error) {
	for {
		if w.reader == nil {
			msgType, r, err := w.c.NextReader()
			if err != nil {
				return 0, err
			}
			if msgType != websocket.BinaryMessage && msgType != websocket.TextMessage {
				continue
			}
			w.reader = r
		}
		n, err := w.reader.Read(b)
		if err == io.EOF {
			w.reader = nil
			continue
		}
		return n, err
	}
}

func (w *wsConn) Write(b []byte) (int, error) {
	if err := w.c.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsConn) Close() error {
	return w.c.Close()
}
