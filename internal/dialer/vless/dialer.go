package vless

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"fmt"
	"net"
	"reflect"
	"strings"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	xuuid "github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy"
	xvless "github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"

	"forward/internal/config"
	"forward/internal/dialer"
	"forward/internal/protocol/vless"
)

func init() {
	dialer.Register("vless", New)
	dialer.Register("vless+reality", New)
}

type Dialer struct {
	proxyDest      xnet.Destination
	userID         *protocol.ID
	flow           string
	streamSettings *internet.MemoryStreamConfig
}

func New(cfg config.Config) (dialer.Dialer, error) {
	ep := cfg.Forward
	if ep == nil {
		return nil, fmt.Errorf("vless dialer requires forward endpoint")
	}

	user := ep.User
	if user == nil {
		return nil, fmt.Errorf("vless uuid is required")
	}
	username := user.Username()
	if username == "" {
		return nil, fmt.Errorf("vless uuid is required")
	}

	uuid, err := vless.ParseUUID(username)
	if err != nil {
		return nil, fmt.Errorf("invalid vless uuid: %w", err)
	}
	parsedUUID, err := xuuid.ParseBytes(uuid[:])
	if err != nil {
		return nil, fmt.Errorf("invalid vless uuid: %w", err)
	}

	host := ep.Host
	port := ep.Port
	proxyDest := xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port))

	q := ep.Query
	security := q.Get("security")
	if security == "" && strings.Contains(ep.Scheme, "reality") {
		security = "reality"
	}
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}

	tp := conf.TransportProtocol(network)
	streamConf := &conf.StreamConfig{
		Network:  &tp,
		Security: security,
	}

	if security == "reality" {
		streamConf.REALITYSettings = &conf.REALITYConfig{
			Show:        false,
			Fingerprint: q.Get("fp"),
			ServerName:  q.Get("sni"),
			PublicKey:   q.Get("pbk"),
			ShortId:     q.Get("sid"),
			SpiderX:     q.Get("u"),
		}
	} else if security == "tls" {
		streamConf.TLSSettings = &conf.TLSConfig{
			ServerName:  q.Get("sni"),
			Fingerprint: q.Get("fp"),
		}
		if q.Get("insecure") == "true" || cfg.Insecure {
			streamConf.TLSSettings.Insecure = true
		}
	}

	pbStreamSettings, err := streamConf.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build stream settings: %w", err)
	}

	memStreamSettings, err := internet.ToMemoryStreamConfig(pbStreamSettings)
	if err != nil {
		return nil, fmt.Errorf("failed to convert stream settings: %w", err)
	}

	return &Dialer{
		proxyDest:      proxyDest,
		userID:         protocol.NewID(parsedUUID),
		flow:           strings.TrimSpace(q.Get("flow")),
		streamSettings: memStreamSettings,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := internet.Dial(ctx, d.proxyDest, d.streamSettings)
	if err != nil {
		return nil, fmt.Errorf("dial proxy failed: %w", err)
	}

	request, requestAddons, err := d.buildRequest(network, address)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if err := encoding.EncodeRequestHeader(conn, request, requestAddons); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless request encode failed: %w", err)
	}

	responseAddons, err := encoding.DecodeResponseHeader(conn, request)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless response decode failed: %w", err)
	}

	trafficState := proxy.NewTrafficState(d.userID.Bytes())
	clientReader := encoding.DecodeBodyAddons(conn, request, responseAddons)
	if requestAddons.Flow == xvless.XRV {
		input, rawInput, err := visionInputBuffers(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		clientReader = proxy.NewVisionReader(clientReader, trafficState, false, ctx, conn, input, rawInput, nil)
	}

	clientWriter := encoding.EncodeBodyAddons(buf.NewWriter(conn), request, requestAddons, trafficState, true, ctx, conn, nil)
	reader := &buf.BufferedReader{Reader: clientReader}

	return &vlessConn{
		Conn:   conn,
		reader: reader,
		writer: clientWriter,
	}, nil
}

type vlessConn struct {
	net.Conn
	reader *buf.BufferedReader
	writer buf.Writer
}

func (c *vlessConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *vlessConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for len(p) > 0 {
		b := buf.New()
		n, err := b.Write(p)
		if err != nil && n == 0 {
			b.Release()
			return written, err
		}
		p = p[n:]
		if err := c.writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

func (d *Dialer) buildRequest(network, address string) (*protocol.RequestHeader, *encoding.Addons, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid target address %q: %w", address, err)
	}
	port, err := xnet.PortFromString(portStr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid target port %q: %w", portStr, err)
	}

	command := protocol.RequestCommandTCP
	if strings.HasPrefix(strings.ToLower(network), "udp") {
		command = protocol.RequestCommandUDP
	}

	flow := d.flow
	allowUDP443 := false
	if flow == xvless.XRV+"-udp443" {
		allowUDP443 = true
		flow = xvless.XRV
	}
	if flow == xvless.XRV && command == protocol.RequestCommandUDP {
		if !allowUDP443 || port != 443 {
			return nil, nil, fmt.Errorf("xtls-rprx-vision does not support udp")
		}
	}

	user := &protocol.MemoryUser{
		Account: &xvless.MemoryAccount{
			ID:   d.userID,
			Flow: flow,
		},
	}

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    user,
		Command: command,
		Address: xnet.ParseAddress(host),
		Port:    port,
	}
	addons := &encoding.Addons{Flow: flow}
	return request, addons, nil
}

func visionInputBuffers(conn net.Conn) (*bytes.Reader, *bytes.Buffer, error) {
	if statConn, ok := conn.(*stat.CounterConnection); ok {
		conn = statConn.Connection
	}
	switch c := conn.(type) {
	case *tls.Conn:
		if c.ConnectionState().Version != gotls.VersionTLS13 {
			return nil, nil, fmt.Errorf("xtls-rprx-vision requires TLS 1.3")
		}
		return xtlsBuffers(c.Conn)
	case *tls.UConn:
		if c.ConnectionState().Version != gotls.VersionTLS13 {
			return nil, nil, fmt.Errorf("xtls-rprx-vision requires TLS 1.3")
		}
		return xtlsBuffers(c.Conn)
	case *reality.UConn:
		return xtlsBuffers(c.Conn)
	default:
		return nil, nil, fmt.Errorf("xtls-rprx-vision requires TLS or REALITY")
	}
}

func xtlsBuffers(conn any) (*bytes.Reader, *bytes.Buffer, error) {
	val := reflect.ValueOf(conn)
	if val.Kind() != reflect.Ptr || val.IsNil() {
		return nil, nil, fmt.Errorf("invalid xtls connection")
	}
	t := val.Type().Elem()
	inputField, ok := t.FieldByName("input")
	if !ok {
		return nil, nil, fmt.Errorf("missing xtls input buffer")
	}
	rawInputField, ok := t.FieldByName("rawInput")
	if !ok {
		return nil, nil, fmt.Errorf("missing xtls rawInput buffer")
	}

	p := unsafe.Pointer(val.Pointer())
	input := (*bytes.Reader)(unsafe.Pointer(uintptr(p) + inputField.Offset))
	rawInput := (*bytes.Buffer)(unsafe.Pointer(uintptr(p) + rawInputField.Offset))
	return input, rawInput, nil
}
