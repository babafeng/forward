package dtls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pion/dtls/v2"

	"forward/base/logging"
	dtlsutil "forward/base/transport/dtls"
	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
)

const (
	defaultBufferSize = 1200
	defaultHandshake  = 30 * time.Second
)

var errMissingAddr = errors.New("missing listen address")
var errMissingTLS = errors.New("missing tls config")

type listenerMetadata struct {
	mtu             int
	bufferSize      int
	flightInterval  time.Duration
	handshakeTimout time.Duration
}

type Listener struct {
	addr    net.Addr
	ln      net.Listener
	logger  *logging.Logger
	md      listenerMetadata
	options listener.Options
}

func init() {
	registry.ListenerRegistry().Register("dtls", NewListener)
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Listener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *Listener) Init(md metadata.Metadata) error {
	l.parseMetadata(md)

	addr := l.options.Addr
	if addr == "" {
		return listener.NewBindError(errMissingAddr)
	}

	tlsCfg := l.options.TLSConfig
	if tlsCfg == nil || len(tlsCfg.Certificates) == 0 {
		return errMissingTLS
	}

	network := "udp"
	if isIPv4(addr) {
		network = "udp4"
	}
	laddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return listener.NewBindError(err)
	}

	cfg := &dtls.Config{
		Certificates:         tlsCfg.Certificates,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), l.md.handshakeTimout)
		},
		ClientCAs:      tlsCfg.ClientCAs,
		ClientAuth:     dtls.ClientAuthType(tlsCfg.ClientAuth),
		FlightInterval: l.md.flightInterval,
		MTU:            l.md.mtu,
	}

	ln, err := dtls.Listen(network, laddr, cfg)
	if err != nil {
		return err
	}
	l.ln = ln
	l.addr = ln.Addr()

	return nil
}

func (l *Listener) Accept() (net.Conn, error) {
	if l.ln == nil {
		return nil, listener.ErrClosed
	}
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, listener.NewAcceptError(err)
	}
	conn = dtlsutil.Conn(conn, l.md.bufferSize)
	return conn, nil
}

func (l *Listener) Addr() net.Addr {
	if l.ln != nil {
		return l.ln.Addr()
	}
	return l.addr
}

func (l *Listener) Close() error {
	if l.ln == nil {
		return nil
	}
	if l.logger != nil && l.ln.Addr() != nil {
		l.logger.Info("Listener closed %s", l.ln.Addr().String())
	}
	return l.ln.Close()
}

func (l *Listener) parseMetadata(md metadata.Metadata) {
	l.md.bufferSize = defaultBufferSize
	l.md.handshakeTimout = defaultHandshake
	if md == nil {
		return
	}
	if v := getInt(md.Get("dtls_mtu")); v > 0 {
		l.md.mtu = v
	}
	if v := getInt(md.Get("mtu")); v > 0 {
		l.md.mtu = v
	}
	if v := getInt(md.Get("dtls_buffer")); v > 0 {
		l.md.bufferSize = v
	}
	if v := getInt(md.Get("buffer_size")); v > 0 {
		l.md.bufferSize = v
	}
	if v := getDuration(md.Get("dtls_flight_interval")); v > 0 {
		l.md.flightInterval = v
	}
	if v := getDuration(md.Get("flight_interval")); v > 0 {
		l.md.flightInterval = v
	}
	if v := getDuration(md.Get("handshake_timeout")); v > 0 {
		l.md.handshakeTimout = v
	}
}

func isIPv4(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.To4() != nil
}

func getInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(t), "%d", &n)
		return n
	default:
		return 0
	}
}

func getDuration(v any) time.Duration {
	switch t := v.(type) {
	case time.Duration:
		return t
	case int:
		return time.Duration(t) * time.Second
	case int64:
		return time.Duration(t) * time.Second
	case float64:
		return time.Duration(t) * time.Second
	case string:
		if d, err := time.ParseDuration(strings.TrimSpace(t)); err == nil {
			return d
		}
		var n int64
		if _, err := fmt.Sscanf(strings.TrimSpace(t), "%d", &n); err == nil {
			return time.Duration(n) * time.Second
		}
		return 0
	default:
		return 0
	}
}
