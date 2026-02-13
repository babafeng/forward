package tproxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	inet "forward/base/io/net"
	"forward/base/logging"
	"forward/internal/chain"
	corehandler "forward/internal/handler"
	"forward/internal/metadata"
	"forward/internal/registry"
	"forward/internal/router"
)

func init() {
	registry.HandlerRegistry().Register("tproxy", NewHandler)
}

type Handler struct {
	options       corehandler.Options
	sniffing      bool
	destOverride  map[string]bool
	sniffTimeout  time.Duration
	udpIdle       time.Duration
	maxUDPSession int
}

type tproxyStats struct {
	logger   *logging.Logger
	started  atomic.Bool
	mu       sync.Mutex
	lastDump time.Time
	last     statsValuesSnapshot
	counts   statsSnapshot
}

type statsSnapshot struct {
	total       atomic.Int64
	finClose    atomic.Int64
	brokenPipe  atomic.Int64
	resetByPeer atomic.Int64
	timeout     atomic.Int64
	other       atomic.Int64
}

type statsValuesSnapshot struct {
	total       int64
	finClose    int64
	brokenPipe  int64
	resetByPeer int64
	timeout     int64
	other       int64
}

var globalTProxyStats tproxyStats

func NewHandler(opts ...corehandler.Option) corehandler.Handler {
	options := corehandler.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	if options.Router == nil {
		options.Router = router.NewStatic(chain.NewRoute())
	}
	if options.Logger != nil {
		initTProxyStats(options.Logger)
	}
	return &Handler{
		options:      options,
		sniffing:     true,
		destOverride: map[string]bool{"http": true, "tls": true, "quic": true},
	}
}

func (h *Handler) Init(md metadata.Metadata) error {
	if md == nil {
		return nil
	}
	if v := md.Get("sniffing"); v != nil {
		h.sniffing = parseBool(v)
	}
	if v := md.Get("dest_override"); v != nil {
		if list := parseStringList(v); len(list) > 0 {
			h.destOverride = map[string]bool{}
			for _, item := range list {
				h.destOverride[strings.ToLower(item)] = true
			}
		}
	}
	if v := md.Get("sniff_timeout"); v != nil {
		if t, ok := v.(time.Duration); ok && t > 0 {
			h.sniffTimeout = t
		}
	}
	if v := md.Get("udp_idle"); v != nil {
		if t, ok := v.(time.Duration); ok && t > 0 {
			h.udpIdle = t
		}
	}
	if v := md.Get("max_udp_sessions"); v != nil {
		if n, ok := v.(int); ok && n > 0 {
			h.maxUDPSession = n
		}
	}
	return nil
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn, opts ...corehandler.HandleOption) error {
	defer conn.Close()

	network := "tcp"
	if _, ok := conn.(net.PacketConn); ok {
		network = "udp"
	}

	md := handleMetadata(opts)
	origAddr := ""
	if md != nil {
		origAddr = md.GetString(metadata.KeyOriginalDst)
	}
	if origAddr == "" && conn.LocalAddr() != nil {
		origAddr = conn.LocalAddr().String()
	}
	if origAddr == "" {
		return errors.New("tproxy handler: missing original destination")
	}

	routeAddr := origAddr
	dialAddr := origAddr
	sniffHost := ""
	sniffProto := ""
	if h.sniffing {
		switch network {
		case "tcp":
			var pre []byte
			pre, sniffHost, sniffProto = sniffTCPConn(conn, h.destOverride, h.sniffTimeout)
			if len(pre) > 0 {
				conn = &prependConn{Conn: conn, buf: pre}
			}
		case "udp":
			var pre []byte
			conn, pre, sniffHost, sniffProto = sniffUDP(conn, h.destOverride, h.sniffTimeout)
			if len(pre) > 0 {
				conn = &prependConn{Conn: conn, buf: pre}
			}
		}
		if sniffHost != "" && shouldOverride(sniffProto, h.destOverride) {
			if _, port := splitHostPort(origAddr); port != "" {
				routeAddr = net.JoinHostPort(sniffHost, port)
			}
		}
	}

	route, err := h.options.Router.Route(ctx, network, routeAddr)
	if err != nil {
		h.options.Logger.Error("TPROXY %s route error: %v ", chain.RouteSummary(route), err)
		return err
	}
	if route == nil {
		route = chain.NewRoute()
	}
	h.options.Logger.Debug("TPROXY route via %s", chain.RouteSummary(route))

	if len(route.Nodes()) > 0 && sniffHost != "" && shouldOverride(sniffProto, h.destOverride) {
		dialAddr = routeAddr
	}

	h.options.Logger.Info("TPROXY %s %s %s -> %s %s", chain.RouteSummary(route), strings.ToUpper(network), conn.RemoteAddr().String(), origAddr, dialAddr)

	up, err := route.Dial(ctx, network, dialAddr)
	if err != nil {
		h.options.Logger.Error("TPROXY dial %s %s error: %v", chain.RouteSummary(route), dialAddr, err)
		return err
	}

	bytes, dur, err := inet.Bidirectional(ctx, conn, up)
	recordTProxyStats(err)
	if err != nil && ctx.Err() == nil {
		h.options.Logger.Error("TPROXY transfer error: %v", err)
	}
	h.options.Logger.Debug("TPROXY closed %s -> %s transferred %d bytes in %s", conn.RemoteAddr().String(), dialAddr, bytes, dur)
	return err
}

func (h *Handler) logf(level logging.Level, format string, args ...any) {
	if h.options.Logger == nil {
		return
	}
	switch level {
	case logging.LevelDebug:
		h.options.Logger.Debug(format, args...)
	case logging.LevelInfo:
		h.options.Logger.Info(format, args...)
	case logging.LevelWarn:
		h.options.Logger.Warn(format, args...)
	case logging.LevelError:
		h.options.Logger.Error(format, args...)
	}
}

func handleMetadata(opts []corehandler.HandleOption) metadata.Metadata {
	if len(opts) == 0 {
		return nil
	}
	hopts := corehandler.HandleOptions{}
	for _, opt := range opts {
		opt(&hopts)
	}
	return hopts.Metadata
}

func parseBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		t = strings.TrimSpace(strings.ToLower(t))
		return t == "1" || t == "true" || t == "yes" || t == "on"
	default:
		return false
	}
}

func parseStringList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case string:
		return splitComma(t)
	default:
		return nil
	}
}

func splitComma(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitHostPort(addr string) (string, string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", ""
	}
	return host, port
}

func shouldOverride(proto string, overrides map[string]bool) bool {
	if proto == "" || overrides == nil {
		return false
	}
	return overrides[strings.ToLower(proto)]
}

type prependConn struct {
	net.Conn
	buf []byte
}

func (c *prependConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func initTProxyStats(logger *logging.Logger) {
	globalTProxyStats.mu.Lock()
	defer globalTProxyStats.mu.Unlock()
	if globalTProxyStats.logger == nil {
		globalTProxyStats.logger = logger
	}
	if globalTProxyStats.started.Load() {
		return
	}
	globalTProxyStats.started.Store(true)
	globalTProxyStats.lastDump = time.Now()
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			dumpTProxyStats()
		}
	}()
}

func dumpTProxyStats() {
	globalTProxyStats.mu.Lock()
	logger := globalTProxyStats.logger
	last := globalTProxyStats.last
	globalTProxyStats.mu.Unlock()

	if logger == nil {
		return
	}

	cur := statsValues(&globalTProxyStats.counts)
	delta := statsDelta(cur, last)
	if delta.total == 0 {
		return
	}
	logger.Info("TPROXY stats last 60s: total=%d fin=%d rst=%d broken_pipe=%d timeout=%d other=%d",
		delta.total, delta.finClose, delta.resetByPeer, delta.brokenPipe, delta.timeout, delta.other)

	globalTProxyStats.mu.Lock()
	globalTProxyStats.last = cur
	globalTProxyStats.lastDump = time.Now()
	globalTProxyStats.mu.Unlock()
}

func statsValues(s *statsSnapshot) statsValuesSnapshot {
	return statsValuesSnapshot{
		total:       s.total.Load(),
		finClose:    s.finClose.Load(),
		brokenPipe:  s.brokenPipe.Load(),
		resetByPeer: s.resetByPeer.Load(),
		timeout:     s.timeout.Load(),
		other:       s.other.Load(),
	}
}

func statsDelta(cur, last statsValuesSnapshot) statsValuesSnapshot {
	return statsValuesSnapshot{
		total:       cur.total - last.total,
		finClose:    cur.finClose - last.finClose,
		brokenPipe:  cur.brokenPipe - last.brokenPipe,
		resetByPeer: cur.resetByPeer - last.resetByPeer,
		timeout:     cur.timeout - last.timeout,
		other:       cur.other - last.other,
	}
}

func recordTProxyStats(err error) {
	globalTProxyStats.counts.total.Add(1)
	if err == nil {
		globalTProxyStats.counts.finClose.Add(1)
		return
	}
	if isTimeoutErr(err) {
		globalTProxyStats.counts.timeout.Add(1)
		return
	}
	if isResetErr(err) {
		globalTProxyStats.counts.resetByPeer.Add(1)
		return
	}
	if isBrokenPipeErr(err) {
		globalTProxyStats.counts.brokenPipe.Add(1)
		return
	}
	globalTProxyStats.counts.other.Add(1)
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "i/o timeout")
}

func isResetErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	return strings.Contains(err.Error(), "connection reset by peer")
}

func isBrokenPipeErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EPIPE) {
		return true
	}
	return strings.Contains(err.Error(), "broken pipe")
}
