package builder

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"forward/base/endpoint"
	baseenc "forward/base/utils/encoding"
	"forward/internal/chain"
	"forward/internal/config"
	"forward/internal/connector"
	"forward/internal/dialer"
	"forward/internal/metadata"
	"forward/internal/registry"

	ctls "forward/internal/config/tls"
)

func BuildRoute(cfg config.Config, hops []endpoint.Endpoint) (chain.Route, error) {
	return buildRouteInternal(cfg, hops, false)
}

// BuildRoutePooled is like BuildRoute but enables pre-warming dial pools on
// non-multiplexing hops.  The caller must eventually close the returned
// route (via chainRoute.Close) to release pool resources.
func BuildRoutePooled(cfg config.Config, hops []endpoint.Endpoint) (chain.Route, error) {
	return buildRouteInternal(cfg, hops, true)
}

func buildRouteInternal(cfg config.Config, hops []endpoint.Endpoint, enablePool bool) (chain.Route, error) {
	if len(hops) == 0 {
		return chain.NewRoute(), nil
	}

	nodes := make([]*chain.Node, 0, len(hops))
	for i, hop := range hops {
		scheme := strings.ToLower(strings.TrimSpace(hop.Scheme))

		connectorName, dialerName, err := resolveTypes(scheme)
		if err != nil {
			return nil, fmt.Errorf("hop %d: %w", i+1, err)
		}

		// VMess/VLESS: check if using WebSocket transport
		if connectorName == "vmess" || connectorName == "vless" {
			q := hop.Query
			// vmess/vless://...?obfs=websocket or ...?type=ws or ...?net=ws
			if strings.EqualFold(q.Get("obfs"), "websocket") || strings.EqualFold(q.Get("type"), "ws") || strings.EqualFold(q.Get("net"), "ws") {
				dialerName = "ws"
			}
		}

		dialerOpts := []dialer.Option{
			dialer.TimeoutOption(cfg.DialTimeout),
			dialer.LoggerOption(cfg.Logger),
		}
		if dialerName == "tls" || dialerName == "http3" || dialerName == "h3" || dialerName == "dtls" || dialerName == "h2" || dialerName == "quic" {
			tlsOpts := ctls.ClientOptions{}
			if dialerName == "http3" || dialerName == "h3" || dialerName == "quic" {
				tlsOpts.NextProtos = []string{"h3"}
			}
			if dialerName == "h2" {
				tlsOpts.NextProtos = []string{"h2"}
			}
			if connectorName == "http2" {
				tlsOpts.NextProtos = []string{"h2"}
			}
			if dialerName == "tls" && connectorName == "http" {
				tlsOpts.NextProtos = []string{"h2", "http/1.1"}
			}
			tlsCfg, err := ctls.ClientConfig(hop, cfg.Insecure, tlsOpts)
			if err != nil {
				return nil, fmt.Errorf("hop %d: tls config: %w", i+1, err)
			}
			dialerOpts = append(dialerOpts, dialer.TLSConfigOption(tlsCfg))
		}

		newDialer := registry.DialerRegistry().Get(dialerName)
		if newDialer == nil {
			return nil, fmt.Errorf("hop %d: dialer %q not registered", i+1, dialerName)
		}
		d := newDialer(dialerOpts...)

		// Dialer 初始化：部分协议需要传入 metadata
		var dialerMD metadata.Metadata
		switch dialerName {
		case "reality", "h2", "h3":
			dialerMD = buildDialerMetadata(hop)
		case "hysteria2":
			dialerMD = buildHysteria2DialerMetadata(hop, cfg.Insecure)
		case "ws":
			dialerMD = buildWSDialerMetadata(hop)
		}
		if err := d.Init(dialerMD); err != nil {
			return nil, fmt.Errorf("hop %d: init dialer: %w", i+1, err)
		}

		newConnector := registry.ConnectorRegistry().Get(connectorName)
		if newConnector == nil {
			return nil, fmt.Errorf("hop %d: connector %q not registered", i+1, connectorName)
		}
		c := newConnector(
			connector.AuthOption(hop.User),
			connector.TimeoutOption(cfg.HandshakeTimeout),
			connector.LoggerOption(cfg.Logger),
		)

		// Connector 初始化：部分协议需要传入 metadata
		var connectorMD metadata.Metadata
		switch connectorName {
		case "vless":
			connectorMD = buildVlessConnectorMetadata(hop)
		case "vmess":
			connectorMD = buildVmessConnectorMetadata(hop)
		case "ss":
			connectorMD = buildSSConnectorMetadata(hop)
		}
		if connectorMD != nil {
			if err := c.Init(connectorMD); err != nil {
				return nil, fmt.Errorf("hop %d: init connector: %w", i+1, err)
			}
		}

		// chainRoute only invokes Transport.Dial on the first hop.
		// Pooling non-first hops adds background overhead without improving
		// the request fast path.
		var tr *chain.Transport
		if enablePool && i == 0 {
			if _, ok := d.(dialer.Multiplexer); !ok {
				muxEnabled, _, _ := parseMuxConfig(hop.Query)
				// Mux-enabled hops already keep long-lived transport sessions and
				// don't benefit from an extra pre-warm dial pool.
				if !(muxEnabled && (connectorName == "vless" || connectorName == "vmess")) {
					poolEnabled, poolSize, poolTTL := parseDialPoolConfig(hop)
					if poolEnabled {
						tr = chain.NewTransportWithPoolConfig(d, c, hop.Address(), poolSize, poolTTL)
					}
				}
			}
		}
		if tr == nil {
			tr = chain.NewTransport(d, c)
		}
		node := chain.NewNode(fmt.Sprintf("%s_%d", scheme, i+1), hop.Address(), tr)
		nodes = append(nodes, node)
	}

	return chain.NewRoute(nodes...), nil
}

// buildDialerMetadata 为 Reality Dialer 构建 metadata
func buildDialerMetadata(hop endpoint.Endpoint) metadata.Metadata {
	q := hop.Query
	mdMap := map[string]any{
		metadata.KeyHost:        hop.Host,
		metadata.KeyPort:        hop.Port,
		metadata.KeySecurity:    q.Get("security"),
		metadata.KeyNetwork:     q.Get("type"),
		metadata.KeySNI:         q.Get("sni"),
		metadata.KeyFingerprint: q.Get("fp"),
		metadata.KeyPublicKey:   q.Get("pbk"),
		metadata.KeyShortID:     q.Get("sid"),
		metadata.KeySpiderX:     q.Get("spiderx"),
		metadata.KeyALPN:        q.Get("alpn"),
		metadata.KeyInsecure:    q.Get("insecure") == "true" || q.Get("insecure") == "1",
	}
	if hop.User != nil {
		if p, ok := hop.User.Password(); ok {
			mdMap["secret"] = p
		}
	}
	return metadata.New(mdMap)
}

// buildVlessConnectorMetadata 为 VLESS Connector 构建 metadata
func buildVlessConnectorMetadata(hop endpoint.Endpoint) metadata.Metadata {
	q := hop.Query
	uuid := ""
	if hop.User != nil {
		uuid = hop.User.Username()
	}
	mdMap := map[string]any{
		metadata.KeyUUID:       uuid,
		metadata.KeyFlow:       q.Get("flow"),
		metadata.KeyEncryption: q.Get("encryption"),
	}
	mux, muxMaxStreams, muxIdle := parseMuxConfig(q)
	mdMap[metadata.KeyMux] = mux
	if muxMaxStreams > 0 {
		mdMap[metadata.KeyMuxMax] = muxMaxStreams
	}
	if muxIdle > 0 {
		mdMap[metadata.KeyMuxIdle] = muxIdle
	}
	return metadata.New(mdMap)
}

// buildVmessConnectorMetadata 为 VMess Connector 构建 metadata
// URL 格式: vmess://security:uuid@host:port?alterId=0
func buildVmessConnectorMetadata(hop endpoint.Endpoint) metadata.Metadata {
	q := hop.Query
	uuid := ""
	security := ""
	if hop.User != nil {
		security = hop.User.Username() // 加密方式在用户名
		if p, ok := hop.User.Password(); ok {
			uuid = p // UUID 在密码
		}
	}
	mdMap := map[string]any{
		metadata.KeyUUID:     uuid,
		metadata.KeySecurity: security,
		metadata.KeyAlterID:  q.Get("alterId"),
	}
	mux, muxMaxStreams, muxIdle := parseMuxConfig(q)
	mdMap[metadata.KeyMux] = mux
	if muxMaxStreams > 0 {
		mdMap[metadata.KeyMuxMax] = muxMaxStreams
	}
	if muxIdle > 0 {
		mdMap[metadata.KeyMuxIdle] = muxIdle
	}
	return metadata.New(mdMap)
}

func buildWSDialerMetadata(hop endpoint.Endpoint) metadata.Metadata {
	q := hop.Query
	mdMap := map[string]any{
		metadata.KeyHost:     q.Get("host"),
		metadata.KeyPath:     q.Get("path"),
		metadata.KeySecurity: q.Get("security"), // e.g. "tls"
		metadata.KeyInsecure: q.Get("insecure") == "true" || q.Get("insecure") == "1",
	}
	return metadata.New(mdMap)
}

// buildSSConnectorMetadata 为 Shadowsocks Connector 构建 metadata
// URL 格式: ss://method:password@host:port
func buildSSConnectorMetadata(hop endpoint.Endpoint) metadata.Metadata {
	method, password := parseSSCredentials(hop.User)
	plugin, pluginMode, pluginHost := parseSSPluginOptions(hop)
	return metadata.New(map[string]any{
		metadata.KeyMethod:   method,
		metadata.KeyPassword: password,
		"plugin":             plugin,
		"plugin_mode":        pluginMode,
		"plugin_host":        pluginHost,
	})
}

func parseSSCredentials(user *url.Userinfo) (method, password string) {
	if user == nil {
		return "", ""
	}
	method = strings.TrimSpace(user.Username())
	if p, ok := user.Password(); ok {
		return method, p
	}

	decoded, ok := baseenc.DecodeBase64Flexible(method)
	if !ok {
		return method, ""
	}
	parts := strings.SplitN(strings.TrimSpace(string(decoded)), ":", 2)
	if len(parts) != 2 {
		return method, ""
	}
	m := strings.TrimSpace(parts[0])
	p := parts[1]
	if m == "" || p == "" {
		return method, ""
	}
	return m, p
}

func parseSSPluginOptions(hop endpoint.Endpoint) (plugin, mode, host string) {
	q := hop.Query
	plugin = strings.TrimSpace(q.Get("plugin"))
	mode = strings.TrimSpace(q.Get("plugin_mode"))
	host = strings.TrimSpace(q.Get("plugin_host"))

	// 兼容 obfs 风格参数键。
	if mode == "" {
		mode = strings.TrimSpace(q.Get("obfs"))
	}
	if host == "" {
		host = strings.TrimSpace(q.Get("obfs-host"))
	}

	rawQuery := rawQueryFromEndpoint(hop.Raw)
	if rawQuery != "" {
		kv := parseLooseQuery(rawQuery)
		if plugin == "" {
			plugin = kv["plugin"]
		}
		if mode == "" {
			mode = kv["plugin_mode"]
			if mode == "" {
				mode = kv["obfs"]
			}
		}
		if host == "" {
			host = kv["plugin_host"]
			if host == "" {
				host = kv["obfs-host"]
			}
		}
	}

	basePlugin, pluginOpts := parseSSPluginSpec(plugin)
	if basePlugin != "" {
		plugin = basePlugin
	}
	if mode == "" {
		mode = pluginOpts["plugin_mode"]
		if mode == "" {
			mode = pluginOpts["obfs"]
		}
	}
	if host == "" {
		host = pluginOpts["plugin_host"]
		if host == "" {
			host = pluginOpts["obfs-host"]
		}
	}

	plugin = normalizeSSPluginName(plugin)
	return strings.TrimSpace(plugin), strings.TrimSpace(mode), strings.TrimSpace(host)
}

func rawQueryFromEndpoint(raw string) string {
	idx := strings.IndexByte(raw, '?')
	if idx < 0 || idx+1 >= len(raw) {
		return ""
	}
	rawQuery := raw[idx+1:]
	if fragIdx := strings.IndexByte(rawQuery, '#'); fragIdx >= 0 {
		return rawQuery[:fragIdx]
	}
	return rawQuery
}

// parseLooseQuery 兼容 `&` 和 `;` 两种分隔符。
func parseLooseQuery(rawQuery string) map[string]string {
	out := make(map[string]string)
	fields := strings.FieldsFunc(rawQuery, func(r rune) bool {
		return r == '&' || r == ';'
	})
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, value, found := strings.Cut(field, "=")
		if !found {
			if decodedField, err := url.QueryUnescape(field); err == nil {
				key, value, found = strings.Cut(decodedField, "=")
			}
		}
		if !found {
			key = field
			value = ""
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if dk, err := url.QueryUnescape(key); err == nil {
			key = dk
		}
		value = strings.TrimSpace(value)
		if dv, err := url.QueryUnescape(value); err == nil {
			value = dv
		}
		out[strings.ToLower(key)] = value
	}
	return out
}

// parseSSPluginSpec 兼容 `plugin=obfs-local;obfs=http;obfs-host=...` 这类写法。
func parseSSPluginSpec(raw string) (string, map[string]string) {
	opts := make(map[string]string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", opts
	}
	if decoded, err := url.QueryUnescape(raw); err == nil {
		raw = decoded
	}
	parts := strings.Split(raw, ";")
	name := strings.TrimSpace(parts[0])
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if k == "" {
			continue
		}
		opts[k] = v
	}
	return name, opts
}

func normalizeSSPluginName(plugin string) string {
	switch strings.ToLower(strings.TrimSpace(plugin)) {
	case "obfs", "obfs-local", "simple-obfs":
		return "obfs"
	default:
		return strings.TrimSpace(plugin)
	}
}

func buildHysteria2DialerMetadata(hop endpoint.Endpoint, cfgInsecure bool) metadata.Metadata {
	q := hop.Query
	auth := ""
	if hop.User != nil {
		raw := hop.User.String()
		decoded, err := url.QueryUnescape(raw)
		if err == nil {
			auth = decoded
		} else {
			auth = raw
		}
	}

	sni := strings.TrimSpace(q.Get("sni"))
	if sni == "" {
		sni = strings.TrimSpace(q.Get("peer"))
	}

	insecure := cfgInsecure
	if rawInsecure := strings.TrimSpace(q.Get("insecure")); rawInsecure != "" {
		if parsed, err := strconv.ParseBool(rawInsecure); err == nil {
			insecure = parsed
		}
	}

	return metadata.New(map[string]any{
		"address":        hop.Address(),
		"auth":           auth,
		"sni":            sni,
		"insecure":       insecure,
		"pinsha256":      strings.TrimSpace(q.Get("pinSHA256")),
		"obfs":           strings.TrimSpace(q.Get("obfs")),
		"obfs_password":  strings.TrimSpace(q.Get("obfs-password")),
		"ca":             strings.TrimSpace(q.Get("ca")),
		metadata.KeyALPN: strings.TrimSpace(q.Get("alpn")),
	})
}

func parseDialPoolConfig(hop endpoint.Endpoint) (enabled bool, poolSize int, poolTTL time.Duration) {
	q := hop.Query

	if rawEnabled := strings.TrimSpace(q.Get("pool")); rawEnabled != "" {
		if v, err := strconv.ParseBool(rawEnabled); err == nil {
			enabled = v
			if !enabled {
				return false, 0, 0
			}
		}
	}

	rawSize := strings.TrimSpace(q.Get("pool_size"))
	if rawSize != "" {
		enabled = true
		if n, err := strconv.Atoi(rawSize); err == nil && n > 0 {
			poolSize = n
		}
	}

	rawTTL := strings.TrimSpace(q.Get("pool_ttl"))
	if rawTTL == "" {
		return enabled, poolSize, 0
	}
	enabled = true

	if d, err := time.ParseDuration(rawTTL); err == nil && d > 0 {
		return enabled, poolSize, d
	}
	if sec, err := strconv.Atoi(rawTTL); err == nil && sec > 0 {
		return enabled, poolSize, time.Duration(sec) * time.Second
	}
	return enabled, poolSize, 0
}

func parseMuxConfig(q url.Values) (enabled bool, maxStreams int, idle time.Duration) {
	rawMux := strings.TrimSpace(q.Get("mux"))
	if rawMux != "" {
		if v, err := strconv.ParseBool(rawMux); err == nil {
			enabled = v
		}
	}

	rawMax := strings.TrimSpace(q.Get("mux_max_streams"))
	if rawMax == "" {
		rawMax = strings.TrimSpace(q.Get("mux_concurrency"))
	}
	if rawMax != "" {
		if n, err := strconv.Atoi(rawMax); err == nil && n > 0 {
			maxStreams = n
		}
	}

	rawIdle := strings.TrimSpace(q.Get("mux_idle"))
	if rawIdle == "" {
		rawIdle = strings.TrimSpace(q.Get("mux_idle_timeout"))
	}
	if rawIdle != "" {
		if d, err := time.ParseDuration(rawIdle); err == nil && d > 0 {
			idle = d
		} else if sec, err := strconv.Atoi(rawIdle); err == nil && sec > 0 {
			idle = time.Duration(sec) * time.Second
		}
	}
	return enabled, maxStreams, idle
}

// schemeTable 将完整 scheme 字符串映射到 [connector, dialer] 对。
// 维护新协议时只需在此处添加一行，无需修改控制流。
var schemeTable = map[string][2]string{
	// HTTP 系列
	"http":         {"http", "tcp"},
	"https":        {"http", "tls"},
	"http+tls":     {"http", "tls"},
	"tls":          {"http", "tls"},
	"http2":        {"http2", "tls"},
	"http3":        {"http3", "http3"},
	"h2":           {"http", "h2"},
	"h3":           {"http", "h3"},
	// SOCKS5
	"socks5":       {"socks5", "tcp"},
	"socks5h":      {"socks5", "tcp"},
	// 裸 TCP / UDP
	"tcp":          {"tcp", "tcp"},
	"quic":         {"tcp", "quic"},
	"dtls":         {"tcp", "dtls"},
	// VLESS
	"vless":        {"vless", "reality"},
	"vless+reality":{"vless", "reality"},
	"reality":      {"vless", "reality"},
	"vless+tls":    {"vless", "tls"},
	// VMess
	"vmess":        {"vmess", "tcp"},
	"vmess+tls":    {"vmess", "tls"},
	// Shadowsocks
	"ss":           {"ss", "tcp"},
	"shadowsocks":  {"ss", "tcp"},
	"ss+tls":       {"ss", "tls"},
	"shadowsocks+tls": {"ss", "tls"},
	// Hysteria2
	"hysteria2":    {"hysteria2", "hysteria2"},
	"hy2":          {"hysteria2", "hysteria2"},
}

// suffixDialerTable 将传输层后缀映射到 dialer 名。
// 支持的 connector 集合见 suffixConnectorTable。
var suffixDialerTable = []struct {
	suffix string
	dialer string
}{
	{"+tls", "tls"},
	{"+h2", "h2"},
	{"+h3", "h3"},
	{"+dtls", "dtls"},
	{"+quic", "quic"},
}

// suffixConnectorTable 列出允许携带传输层后缀的 connector。
var suffixConnectorTable = map[string]string{
	"http":        "http",
	"socks5":      "socks5",
	"socks5h":     "socks5",
	"tcp":         "tcp",
	"vless":       "vless",
	"vmess":       "vmess",
	"ss":          "ss",
	"shadowsocks": "ss",
}

func resolveTypes(scheme string) (connectorName, dialerName string, err error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		return "", "", fmt.Errorf("unsupported scheme: %s", scheme)
	}

	// 优先查静态表
	if pair, ok := schemeTable[scheme]; ok {
		return pair[0], pair[1], nil
	}

	// 处理 "base+transport" 复合 scheme
	for _, entry := range suffixDialerTable {
		base, found := strings.CutSuffix(scheme, entry.suffix)
		if !found {
			continue
		}
		// 先检查基础 scheme 是否在静态表（整体已匹配，不走后缀）
		if _, ok := schemeTable[scheme]; ok {
			break
		}
		conn, ok := suffixConnectorTable[base]
		if !ok {
			return "", "", fmt.Errorf("unsupported scheme: %s", scheme)
		}
		return conn, entry.dialer, nil
	}

	return "", "", fmt.Errorf("unsupported scheme: %s", scheme)
}

// BuildHysteria2DialerMetadata is the exported wrapper for buildHysteria2DialerMetadata.
func BuildHysteria2DialerMetadata(hop endpoint.Endpoint, cfgInsecure bool) metadata.Metadata {
	return buildHysteria2DialerMetadata(hop, cfgInsecure)
}

// ResolveTypes is the exported wrapper for resolveTypes.
func ResolveTypes(scheme string) (connectorName, dialerName string, err error) {
	return resolveTypes(scheme)
}
