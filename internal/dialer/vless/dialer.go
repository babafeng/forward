package vless

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
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
	dialer.Register("reality", New)
}

type Dialer struct {
	proxyDest      xnet.Destination
	userID         *protocol.ID
	flow           string
	encryption     string
	streamSettings *internet.MemoryStreamConfig
	streamNetwork  string
	base           dialer.Dialer
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

	alpn := strings.Split(q.Get("alpn"), ",")
	if len(alpn) == 1 && alpn[0] == "" {
		alpn = nil
	}
	fpOrDefault := func(fp string) string {
		if fp == "" {
			return "chrome"
		}
		return fp
	}

	switch security {
	case "reality":
		streamConf.REALITYSettings = &conf.REALITYConfig{
			Show:        false,
			Fingerprint: fpOrDefault(q.Get("fp")),
			ServerName:  q.Get("sni"),
			PublicKey:   q.Get("pbk"),
			ShortId:     q.Get("sid"),
			SpiderX:     q.Get("u"),
		}
	case "tls":
		var alpnList *conf.StringList
		if len(alpn) > 0 {
			sl := conf.StringList(alpn)
			alpnList = &sl
		}
		streamConf.TLSSettings = &conf.TLSConfig{
			ServerName:  q.Get("sni"),
			Fingerprint: fpOrDefault(q.Get("fp")),
			ALPN:        alpnList,
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
		encryption:     strings.TrimSpace(q.Get("encryption")),
		streamSettings: memStreamSettings,
		streamNetwork:  network,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dialProxy(ctx)
	if err != nil {
		return nil, err
	}

	request, requestAddons, err := d.buildRequest(network, address)
	if err != nil {
		conn.Close()
		return nil, err
	}

	trafficState := proxy.NewTrafficState(d.userID.Bytes())
	bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
	if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless request encode failed: %w", err)
	}
	clientWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, nil)
	if requestAddons.Flow == xvless.XRV {
		if err := clientWriter.WriteMultiBuffer(make(buf.MultiBuffer, 1)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("vless vision padding failed: %w", err)
		}
	}
	if err := bufferWriter.SetBuffered(false); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless flush failed: %w", err)
	}

	return &vlessConn{
		Conn:   conn,
		reader: nil,
		writer: clientWriter,
		ctx:    ctx,
		req:    request,
		addons: requestAddons,
		state:  trafficState,
	}, nil
}

func (d *Dialer) SetBase(base dialer.Dialer) {
	if base == nil {
		return
	}
	d.base = base
}

func (d *Dialer) dialProxy(ctx context.Context) (net.Conn, error) {
	if d.base == nil {
		conn, err := internet.Dial(ctx, d.proxyDest, d.streamSettings)
		if err != nil {
			return nil, fmt.Errorf("dial proxy failed: %w", err)
		}
		return conn, nil
	}

	transport := strings.ToLower(strings.TrimSpace(d.streamSettings.ProtocolName))
	if transport == "" {
		transport = strings.ToLower(strings.TrimSpace(d.streamNetwork))
	}
	if transport != "tcp" {
		return nil, fmt.Errorf("vless chain only supports tcp transport, got %s", transport)
	}

	conn, err := d.base.DialContext(ctx, "tcp", d.proxyDest.NetAddr())
	if err != nil {
		return nil, fmt.Errorf("dial proxy failed: %w", err)
	}

	if tlsConfig := tls.ConfigFromStreamSettings(d.streamSettings); tlsConfig != nil {
		tlsConf := tlsConfig.GetTLSConfig(tls.WithDestination(d.proxyDest))
		if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
			conn = tls.UClient(conn, tlsConf, fingerprint)
			if err := conn.(*tls.UConn).HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("vless tls handshake failed: %w", err)
			}
		} else {
			conn = tls.Client(conn, tlsConf)
			if err := conn.(*tls.Conn).HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("vless tls handshake failed: %w", err)
			}
		}
	} else if realityConfig := reality.ConfigFromStreamSettings(d.streamSettings); realityConfig != nil {
		var err error
		conn, err = reality.UClient(conn, realityConfig, ctx, d.proxyDest)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("vless reality handshake failed: %w", err)
		}
	}

	return conn, nil
}

type vlessConn struct {
	net.Conn
	reader *buf.BufferedReader
	writer buf.Writer

	ctx    context.Context
	req    *protocol.RequestHeader
	addons *encoding.Addons
	state  *proxy.TrafficState

	initOnce     sync.Once
	initErr      error
	directReader bool
}

func (c *vlessConn) Read(p []byte) (int, error) {
	if err := c.initReader(); err != nil {
		return 0, err
	}
	if c.state != nil && c.state.Outbound.DownlinkReaderDirectCopy && !c.directReader {
		rawConn, _, _ := proxy.UnwrapRawConn(c.Conn)
		c.reader = &buf.BufferedReader{Reader: buf.NewReader(rawConn)}
		c.directReader = true
	}
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

func (c *vlessConn) initReader() error {
	c.initOnce.Do(func() {
		responseAddons, err := encoding.DecodeResponseHeader(c.Conn, c.req)
		if err != nil {
			c.initErr = fmt.Errorf("vless response decode failed: %w", err)
			return
		}

		reader := encoding.DecodeBodyAddons(c.Conn, c.req, responseAddons)
		if c.addons != nil && c.addons.Flow == xvless.XRV {
			input, rawInput, err := visionInputBuffers(c.Conn)
			if err != nil {
				c.initErr = err
				return
			}
			reader = proxy.NewVisionReader(reader, c.state, false, c.ctx, c.Conn, input, rawInput, nil)
		}
		c.reader = &buf.BufferedReader{Reader: reader}
	})
	return c.initErr
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
			ID:         d.userID,
			Flow:       flow,
			Encryption: encryptionValue(d.encryption),
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

func encryptionValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "none"
	}
	return v
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
		if c.UConn == nil || c.UConn.Conn == nil {
			return nil, nil, fmt.Errorf("xtls-rprx-vision requires valid tls uconn")
		}
		return xtlsBuffers(c.UConn.Conn)
	case *reality.UConn:
		if c.UConn == nil || c.UConn.Conn == nil {
			return nil, nil, fmt.Errorf("xtls-rprx-vision requires valid reality uconn")
		}
		return xtlsBuffers(c.UConn.Conn)
	case *reality.Conn:
		return xtlsBuffers(c)
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
	if input == nil || rawInput == nil {
		return nil, nil, fmt.Errorf("xtls input buffers not initialized")
	}
	return input, rawInput, nil
}
