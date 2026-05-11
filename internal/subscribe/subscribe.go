// Package subscribe 实现订阅链接的下载、解析和管理。
// 支持 Clash YAML 和 base64 编码的代理 URI 列表两种格式。
package subscribe

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"forward/base/endpoint"
	baseenc "forward/base/utils/encoding"

	"gopkg.in/yaml.v3"
)

// ClashConfig 表示 Clash 订阅 YAML 的顶层结构，仅关注 proxies 字段。
type ClashConfig struct {
	Proxies []ClashProxy `yaml:"proxies"`
}

// ClashProxy 表示 Clash 中的单个代理节点。
type ClashProxy struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`                       // vmess, ss, trojan, vless, hysteria2, socks5, http ...
	Server   string `yaml:"server"`                     // 服务器地址
	Port     int    `yaml:"port"`                       // 端口
	UUID     string `yaml:"uuid"`                       // VMess/VLESS UUID
	AlterID  int    `yaml:"alterId"`                    // VMess alterID
	Cipher   string `yaml:"cipher"`                     // 加密方式
	UDP      bool   `yaml:"udp"`                        // 是否支持 UDP
	Username string `yaml:"username"`                   // SOCKS5/HTTP 用户名
	Password string `yaml:"password"`                   // SS/Trojan/SOCKS5/HTTP 密码
	TLS      bool   `yaml:"tls"`                        // 是否启用 TLS
	SNI      string `yaml:"sni"`                        // TLS SNI
	Network  string `yaml:"network"`                    // 传输网络 (ws, grpc 等)
	Insecure bool   `yaml:"insecure,omitempty"`         // 是否跳过 TLS 证书校验
	SkipCert bool   `yaml:"skip-cert-verify,omitempty"` // Clash 兼容字段，是否跳过 TLS 证书校验

	Plugin     string         `yaml:"plugin,omitempty"`      // Shadowsocks 插件名称
	PluginOpts map[string]any `yaml:"plugin-opts,omitempty"` // Shadowsocks 插件参数

	// VLESS 特有字段
	Flow              string          `yaml:"flow,omitempty"`               // VLESS flow (e.g. xtls-rprx-vision)
	ServerName        string          `yaml:"servername,omitempty"`         // TLS/Reality SNI
	ClientFingerprint string          `yaml:"client-fingerprint,omitempty"` // uTLS 指纹
	RealityOpts       *RealityOptions `yaml:"reality-opts,omitempty"`       // Reality 选项
	Mux               bool            `yaml:"mux,omitempty"`                // 是否启用 Xray Mux
	MuxMaxStreams     int             `yaml:"mux-max-streams,omitempty"`    // Mux 最大并发流
	MuxIdle           string          `yaml:"mux-idle,omitempty"`           // Mux 空闲超时

	// WebSocket 选项
	WSOpts *WSOptions `yaml:"ws-opts,omitempty"`
}

// RealityOptions 表示 VLESS Reality 传输选项。
type RealityOptions struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

// WSOptions 表示 WebSocket 传输选项。
type WSOptions struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
}

// IsLocalPath 判断给定的字符串是否为本地文件路径。
// 支持 file:// 协议、绝对路径（/...）以及相对路径（不以 http:// 或 https:// 开头）。
func IsLocalPath(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	if strings.HasPrefix(lower, "file://") {
		return true
	}
	// 不是 http/https 链接且不含 ://（排除其他协议），视为本地路径
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		if !strings.Contains(rawURL, "://") {
			return true
		}
	}
	return false
}

// Download 从指定 URL 或本地文件路径加载订阅内容。
// 若 rawURL 以 file:// 开头，或不含 :// 协议（即为本地路径），则直接读取本地文件；
// 否则通过 HTTP GET 下载。
func Download(rawURL string) ([]byte, error) {
	if IsLocalPath(rawURL) {
		return loadLocalFile(rawURL)
	}
	return downloadHTTP(rawURL)
}

// loadLocalFile 从本地文件系统读取订阅文件。
func loadLocalFile(rawPath string) ([]byte, error) {
	// 去掉 file:// 前缀，并展开 ~ 为用户主目录
	path := strings.TrimPrefix(rawPath, "file://")
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("获取用户主目录失败: %w", err)
		}
		path = filepath.Join(homeDir, path[2:])
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取本地订阅文件失败: %w", err)
	}
	return data, nil
}

// downloadHTTP 通过 HTTP GET 下载订阅内容。
func downloadHTTP(rawURL string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("下载订阅链接失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("下载订阅链接返回状态码 %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取订阅内容失败: %w", err)
	}
	return data, nil
}

// Parse 解析订阅数据为代理节点列表。
// 自动检测格式：Clash YAML / base64 编码的 YAML / base64 编码的 URI 列表 / 纯文本 URI 列表。
func Parse(data []byte) ([]ClashProxy, error) {
	text := strings.TrimSpace(string(data))

	// 1. 先尝试 Clash YAML
	if proxies, err := parseClashYAML([]byte(text)); err == nil && len(proxies) > 0 {
		return normalizeProxyNames(proxies), nil
	}

	// 2. 尝试 base64 解码
	if decoded, err := tryBase64Decode(text); err == nil {
		decodedStr := strings.TrimSpace(string(decoded))

		// 2a. 解码后尝试 Clash YAML
		if proxies, err := parseClashYAML([]byte(decodedStr)); err == nil && len(proxies) > 0 {
			return normalizeProxyNames(proxies), nil
		}

		// 2b. 解码后尝试 URI 列表
		if proxies, err := parseURIList(decodedStr); err == nil && len(proxies) > 0 {
			return normalizeProxyNames(proxies), nil
		}
	}

	// 3. 尝试纯文本 URI 列表
	if proxies, err := parseURIList(text); err == nil && len(proxies) > 0 {
		return normalizeProxyNames(proxies), nil
	}

	return nil, fmt.Errorf("订阅内容格式无法识别（不是 Clash YAML 也不是代理 URI 列表）")
}

// parseClashYAML 解析 Clash YAML 格式。
func parseClashYAML(data []byte) ([]ClashProxy, error) {
	var cfg ClashConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	// 清理字段中可能存在的前导/尾随空白字符（例如 YAML 中的 Tab）
	for i := range cfg.Proxies {
		cfg.Proxies[i].UUID = strings.TrimSpace(cfg.Proxies[i].UUID)
		cfg.Proxies[i].Name = strings.TrimSpace(cfg.Proxies[i].Name)
		cfg.Proxies[i].Server = strings.TrimSpace(cfg.Proxies[i].Server)
		cfg.Proxies[i].Username = strings.TrimSpace(cfg.Proxies[i].Username)
		cfg.Proxies[i].Password = strings.TrimSpace(cfg.Proxies[i].Password)
	}
	return cfg.Proxies, nil
}

// tryBase64Decode 尝试 base64 解码，同时支持标准和 URL-safe 编码，以及有无 padding 的情况。
func tryBase64Decode(s string) ([]byte, error) {
	// 移除可能的空白字符
	s = strings.Join(strings.Fields(s), "")
	if v, ok := baseenc.DecodeBase64Flexible(s); ok {
		return v, nil
	}
	return nil, fmt.Errorf("不是有效的 base64 编码")
}

// 代理 URI 协议前缀
var proxySchemes = []string{"vmess://", "vless://", "ss://", "ssr://", "trojan://", "hysteria2://", "hy2://", "hysteria://"}

// parseURIList 解析每行一个代理 URI 的文本。
func parseURIList(text string) ([]ClashProxy, error) {
	lines := strings.Split(text, "\n")
	var proxies []ClashProxy
	for _, line := range lines {
		line = strings.TrimSpace(line)
		line = strings.Trim(line, `"'`)
		if line == "" {
			continue
		}

		// 检查是否是已知的代理 URI 前缀
		isProxy := false
		for _, scheme := range proxySchemes {
			if strings.HasPrefix(strings.ToLower(line), scheme) {
				isProxy = true
				break
			}
		}
		if !isProxy {
			continue
		}

		proxy, err := parseProxyURI(line)
		if err != nil {
			// 跳过解析失败的 URI，继续处理其他行
			continue
		}
		proxies = append(proxies, proxy)
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("未找到可解析的代理 URI")
	}
	return proxies, nil
}

// parseProxyURI 根据 URI scheme 解析单个代理 URI 为 ClashProxy。
func parseProxyURI(uri string) (ClashProxy, error) {
	lower := strings.ToLower(uri)
	switch {
	case strings.HasPrefix(lower, "vmess://"):
		return parseVmessURI(uri)
	case strings.HasPrefix(lower, "vless://"):
		return parseVlessURI(uri)
	case strings.HasPrefix(lower, "ss://"):
		return parseSSURI(uri)
	case strings.HasPrefix(lower, "trojan://"):
		return parseTrojanURI(uri)
	case strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hy2://"):
		return parseHy2URI(uri)
	default:
		return ClashProxy{}, fmt.Errorf("不支持的代理 URI: %s", uri)
	}
}

// vmessJSON 表示 vmess:// URI 中 base64 编码的 JSON 结构。
type vmessJSON struct {
	V    interface{} `json:"v"`    // 版本号，可能是字符串或数字
	PS   string      `json:"ps"`   // 节点名称
	Add  string      `json:"add"`  // 服务器地址
	Port interface{} `json:"port"` // 端口，可能是字符串或数字
	ID   string      `json:"id"`   // UUID
	Aid  interface{} `json:"aid"`  // alterID，可能是字符串或数字
	Net  string      `json:"net"`  // 传输网络
	Type string      `json:"type"` // 伪装类型
	Host string      `json:"host"` // WebSocket Host / HTTP Host
	Path string      `json:"path"` // WebSocket Path
	TLS  string      `json:"tls"`  // TLS（"tls" 或 ""）
	SNI  string      `json:"sni"`  // TLS SNI
	Scy  string      `json:"scy"`  // 加密方式
}

// parseVmessURI 解析 vmess:// URI。
func parseVmessURI(uri string) (ClashProxy, error) {
	// 支持两类常见格式：
	//   vmess://base64EncodedJSON
	//   vmess://security:uuid@server:port?alterId=0
	payload, suffix := splitVmessPayload(trimVmessScheme(uri))

	if strings.Contains(payload, "@") {
		return parseVmessEndpointURI(uri)
	}

	decoded, err := tryBase64Decode(payload)
	if err == nil {
		if proxy, err := parseVmessJSON(decoded); err == nil {
			return proxy, nil
		}

		decodedText := strings.TrimSpace(string(decoded))
		if decodedText != "" && strings.Contains(decodedText, "@") {
			endpointURI := ensureVmessScheme(decodedText) + suffix
			if proxy, err := parseVmessEndpointURI(endpointURI); err == nil {
				return proxy, nil
			}
		}
	}

	return parseVmessEndpointURI(uri)
}

func parseVmessJSON(decoded []byte) (ClashProxy, error) {
	var v vmessJSON
	if err := json.Unmarshal(decoded, &v); err != nil {
		return ClashProxy{}, fmt.Errorf("vmess URI JSON 解析失败: %w", err)
	}

	port := toInt(v.Port)
	aid := toInt(v.Aid)
	cipher := v.Scy
	if cipher == "" {
		cipher = "auto"
	}

	proxy := ClashProxy{
		Name:    v.PS,
		Type:    "vmess",
		Server:  v.Add,
		Port:    port,
		UUID:    v.ID,
		AlterID: aid,
		Cipher:  cipher,
		TLS:     strings.EqualFold(v.TLS, "tls"),
		SNI:     v.SNI,
		Network: v.Net,
	}

	// WebSocket 选项
	if strings.EqualFold(v.Net, "ws") {
		proxy.WSOpts = &WSOptions{
			Path: v.Path,
		}
		if v.Host != "" {
			proxy.WSOpts.Headers = map[string]string{"Host": v.Host}
		}
	}

	if proxy.Name == "" {
		proxy.Name = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
	}

	return proxy, nil
}

func parseVmessEndpointURI(uri string) (ClashProxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return ClashProxy{}, fmt.Errorf("vmess URI 解析失败: %w", err)
	}
	if u.Hostname() == "" || u.Port() == "" || u.User == nil {
		return ClashProxy{}, fmt.Errorf("vmess URI endpoint 格式错误")
	}

	uuid, _ := u.User.Password()
	if uuid == "" {
		return ClashProxy{}, fmt.Errorf("vmess URI 缺少 UUID")
	}

	port, _ := strconv.Atoi(u.Port())
	query := u.Query()
	cipher := u.User.Username()
	if cipher == "" {
		cipher = query.Get("scy")
	}
	if cipher == "" {
		cipher = query.Get("cipher")
	}
	if cipher == "" {
		cipher = "auto"
	}

	name := query.Get("remarks")
	if name == "" {
		name = query.Get("remark")
	}
	if name == "" {
		name = query.Get("name")
	}
	if name == "" {
		name = query.Get("ps")
	}
	if name == "" && u.Fragment != "" {
		name, _ = url.PathUnescape(u.Fragment)
	}

	network := query.Get("type")
	if network == "" {
		network = query.Get("net")
	}

	proxy := ClashProxy{
		Name:    name,
		Type:    "vmess",
		Server:  u.Hostname(),
		Port:    port,
		UUID:    uuid,
		AlterID: toInt(firstNonEmpty(query.Get("alterId"), query.Get("aid"))),
		Cipher:  cipher,
		TLS:     strings.EqualFold(u.Scheme, "vmess+tls") || strings.EqualFold(query.Get("security"), "tls") || strings.EqualFold(query.Get("tls"), "tls") || strings.EqualFold(query.Get("tls"), "true"),
		SNI:     firstNonEmpty(query.Get("sni"), query.Get("servername")),
		Network: network,
	}

	if strings.EqualFold(proxy.Network, "ws") || strings.EqualFold(proxy.Network, "websocket") {
		proxy.Network = "ws"
		proxy.WSOpts = &WSOptions{
			Path: query.Get("path"),
		}
		if host := query.Get("host"); host != "" {
			proxy.WSOpts.Headers = map[string]string{"Host": host}
		}
	}

	if proxy.Name == "" {
		proxy.Name = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
	}

	return proxy, nil
}

func trimVmessScheme(uri string) string {
	if strings.HasPrefix(strings.ToLower(uri), "vmess://") {
		return uri[len("vmess://"):]
	}
	return uri
}

func ensureVmessScheme(s string) string {
	if strings.Contains(strings.ToLower(s), "://") {
		return s
	}
	return "vmess://" + s
}

func splitVmessPayload(payload string) (string, string) {
	idx := len(payload)
	if q := strings.Index(payload, "?"); q >= 0 && q < idx {
		idx = q
	}
	if f := strings.Index(payload, "#"); f >= 0 && f < idx {
		idx = f
	}
	return payload[:idx], payload[idx:]
}

// parseVlessURI 解析 vless:// URI。
// 格式: vless://uuid@server:port?type=ws&security=tls&sni=xxx&path=/xxx#name
func parseVlessURI(uri string) (ClashProxy, error) {
	uri = strings.TrimSpace(uri)
	// 提取 fragment 作为节点名称
	name := ""
	if idx := strings.LastIndex(uri, "#"); idx >= 0 {
		name, _ = url.PathUnescape(uri[idx+1:])
		uri = uri[:idx]
	}

	ep, err := endpoint.Parse(uri)
	if err != nil {
		return ClashProxy{}, fmt.Errorf("vless URI 解析失败: %w", err)
	}

	uuid := endpoint.UserSecret(ep.User)
	query := ep.Query
	security := strings.TrimSpace(query.Get("security"))
	sni := firstNonEmpty(query.Get("sni"), query.Get("peer"))
	flow := strings.TrimSpace(query.Get("flow"))
	if flow == "" && query.Get("xtls") != "" {
		flow = "xtls-rprx-vision"
	}
	fp := firstNonEmpty(query.Get("fp"), query.Get("client-fingerprint"))
	mux, _ := strconv.ParseBool(strings.TrimSpace(query.Get("mux")))
	muxMaxStreams, _ := strconv.Atoi(strings.TrimSpace(firstNonEmpty(query.Get("mux_max_streams"), query.Get("mux_concurrency"))))
	muxIdle := firstNonEmpty(query.Get("mux_idle"), query.Get("mux_idle_timeout"))

	proxy := ClashProxy{
		Name:              firstNonEmpty(name, query.Get("remarks")),
		Type:              "vless",
		Server:            ep.Host,
		Port:              ep.Port,
		UUID:              uuid,
		TLS:               strings.EqualFold(security, "tls") || strings.EqualFold(security, "reality") || query.Get("tls") == "1" || strings.EqualFold(query.Get("tls"), "true"),
		SNI:               sni,
		ServerName:        sni,
		Network:           firstNonEmpty(query.Get("type"), query.Get("net")),
		Flow:              flow,
		ClientFingerprint: fp,
		Mux:               mux,
		MuxMaxStreams:     muxMaxStreams,
		MuxIdle:           muxIdle,
	}
	if proxy.Network == "" {
		proxy.Network = "tcp"
	}
	if query.Get("pbk") != "" || query.Get("sid") != "" || strings.EqualFold(security, "reality") {
		proxy.TLS = true
		proxy.RealityOpts = &RealityOptions{
			PublicKey: query.Get("pbk"),
			ShortID:   query.Get("sid"),
		}
	}

	if strings.EqualFold(proxy.Network, "ws") {
		proxy.WSOpts = &WSOptions{
			Path: query.Get("path"),
		}
		if host := query.Get("host"); host != "" {
			proxy.WSOpts.Headers = map[string]string{"Host": host}
		}
	}

	if proxy.Name == "" {
		proxy.Name = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
	}

	return proxy, nil
}

// parseSSURI 解析 ss:// URI。
// 格式1: ss://base64(method:password)@server:port?plugin=...#name
// 格式2: ss://base64(method:password@server:port)#name
func parseSSURI(uri string) (ClashProxy, error) {
	name := ""
	if idx := strings.LastIndex(uri, "#"); idx >= 0 {
		name, _ = url.PathUnescape(uri[idx+1:])
		uri = uri[:idx]
	}

	content := strings.TrimPrefix(uri, "ss://")

	// 分离查询参数
	queryStr := ""
	if qIdx := strings.Index(content, "?"); qIdx >= 0 {
		queryStr = content[qIdx+1:]
		content = content[:qIdx]
	}

	var method, password, server string
	var port int

	if atIdx := strings.LastIndex(content, "@"); atIdx >= 0 {
		// 格式1
		userInfoEncoded := content[:atIdx]
		hostPort := content[atIdx+1:]
		decoded, err := tryBase64Decode(userInfoEncoded)
		if err != nil {
			decoded = []byte(userInfoEncoded)
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return ClashProxy{}, fmt.Errorf("ss URI userinfo 格式错误")
		}
		method, password = parts[0], parts[1]
		host, portStr, err := splitHostPort(hostPort)
		if err != nil {
			return ClashProxy{}, fmt.Errorf("ss URI host:port 解析失败: %w", err)
		}
		server = host
		port, _ = strconv.Atoi(portStr)
	} else {
		// 格式2
		decoded, err := tryBase64Decode(content)
		if err != nil {
			return ClashProxy{}, fmt.Errorf("ss URI base64 解码失败: %w", err)
		}
		decodedStr := string(decoded)
		atIdx = strings.LastIndex(decodedStr, "@")
		if atIdx < 0 {
			return ClashProxy{}, fmt.Errorf("ss URI 格式错误: 缺少 @")
		}
		parts := strings.SplitN(decodedStr[:atIdx], ":", 2)
		if len(parts) != 2 {
			return ClashProxy{}, fmt.Errorf("ss URI userinfo 格式错误")
		}
		method, password = parts[0], parts[1]
		host, portStr, err := splitHostPort(decodedStr[atIdx+1:])
		if err != nil {
			return ClashProxy{}, fmt.Errorf("ss URI host:port 解析失败: %w", err)
		}
		server = host
		port, _ = strconv.Atoi(portStr)
	}

	proxy := ClashProxy{
		Name:     name,
		Type:     "ss",
		Server:   server,
		Port:     port,
		Cipher:   method,
		Password: password,
	}

	if queryStr != "" {
		kv := parseLooseQuery(queryStr)
		plugin := kv["plugin"]
		mode := kv["plugin_mode"]
		if mode == "" {
			mode = kv["obfs"]
		}
		host := kv["plugin_host"]
		if host == "" {
			host = kv["obfs-host"]
		}

		// 解析 plugin 内部的值（形如 obfs-local;obfs=http）
		basePlugin, pOpts := parseSSPlugin(plugin)
		if basePlugin != "" {
			plugin = basePlugin
		}
		if mode == "" {
			if m, ok := pOpts["mode"].(string); ok {
				mode = m
			}
		}
		if host == "" {
			if h, ok := pOpts["host"].(string); ok {
				host = h
			}
		}
		uriPath := kv["obfs-uri"]
		if uriPath == "" {
			if u, ok := pOpts["uri"].(string); ok {
				uriPath = u
			}
		}

		// obfs-local => obfs
		if strings.ToLower(plugin) == "obfs-local" || strings.ToLower(plugin) == "simple-obfs" {
			plugin = "obfs"
		}

		if plugin != "" {
			proxy.Plugin = plugin
			proxy.PluginOpts = make(map[string]any)
			if mode != "" {
				proxy.PluginOpts["mode"] = mode
			}
			if host != "" {
				proxy.PluginOpts["host"] = host
			}
			if uriPath != "" {
				proxy.PluginOpts["uri"] = uriPath
			}
		}
	}

	if proxy.Name == "" {
		proxy.Name = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
	}

	return proxy, nil
}

// parseLooseQuery 解析查询字符串，支持 & 和 ; 分隔，并能处理未被预先解码的 %3D。
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

// parseSSPlugin 解析 ss URI 中 plugin 查询参数的值。
// 支持分号分隔格式: "obfs-local;obfs=http;obfs-host=example.com;obfs-uri=/"
// 返回插件名称和选项 map（key 统一为 Clash plugin-opts 格式）。
func parseSSPlugin(pluginParam string) (pluginName string, opts map[string]any) {
	opts = make(map[string]any)
	parts := strings.Split(pluginParam, ";")
	if len(parts) == 0 {
		return "", opts
	}
	pluginName = strings.TrimSpace(parts[0])
	for _, kv := range parts[1:] {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		eqIdx := strings.IndexByte(kv, '=')
		if eqIdx < 0 {
			opts[kv] = true
			continue
		}
		k := kv[:eqIdx]
		v, _ := url.QueryUnescape(kv[eqIdx+1:])
		// 统一字段名为 Clash plugin-opts 格式
		switch k {
		case "obfs":
			opts["mode"] = v
		case "obfs-host":
			opts["host"] = v
		case "obfs-uri":
			opts["uri"] = v
		default:
			opts[k] = v
		}
	}
	return pluginName, opts
}

// parseTrojanURI 解析 trojan:// URI。
// 格式: trojan://password@server:port?sni=xxx#name
func parseTrojanURI(uri string) (ClashProxy, error) {
	name := ""
	if idx := strings.LastIndex(uri, "#"); idx >= 0 {
		name, _ = url.PathUnescape(uri[idx+1:])
		uri = uri[:idx]
	}

	u, err := url.Parse(uri)
	if err != nil {
		return ClashProxy{}, fmt.Errorf("trojan URI 解析失败: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	password := u.User.Username()
	query := u.Query()

	proxy := ClashProxy{
		Name:     name,
		Type:     "trojan",
		Server:   u.Hostname(),
		Port:     port,
		Password: password,
		TLS:      true, // Trojan 默认启用 TLS
		SNI:      query.Get("sni"),
	}

	if proxy.Name == "" {
		proxy.Name = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
	}

	return proxy, nil
}

// parseHy2URI 解析 hysteria2:// 或 hy2:// URI。
// 格式: hysteria2://password@server:port?sni=xxx#name
func parseHy2URI(uri string) (ClashProxy, error) {
	uri = strings.Trim(uri, `"'`)
	name := ""
	if idx := strings.LastIndex(uri, "#"); idx >= 0 {
		name, _ = url.PathUnescape(uri[idx+1:])
		uri = uri[:idx]
	}

	ep, err := endpoint.Parse(uri)
	if err != nil {
		return ClashProxy{}, fmt.Errorf("hy2 URI 解析失败: %w", err)
	}

	query := ep.Query

	proxy := ClashProxy{
		Name:     name,
		Type:     "hysteria2",
		Server:   ep.Host,
		Port:     ep.Port,
		Password: endpoint.UserSecret(ep.User),
		TLS:      true,
		SNI:      firstNonEmpty(query.Get("sni"), query.Get("peer")),
		Insecure: boolQueryValue(query, "insecure", "skip-cert-verify", "allowInsecure"),
	}

	if proxy.Name == "" {
		proxy.Name = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
	}

	return proxy, nil
}

// splitHostPort 拆分 host:port 字符串。
func splitHostPort(hostPort string) (string, string, error) {
	// 处理 IPv6 地址 [::1]:port
	if strings.HasPrefix(hostPort, "[") {
		end := strings.Index(hostPort, "]")
		if end < 0 {
			return "", "", fmt.Errorf("无效的 IPv6 地址: %s", hostPort)
		}
		host := hostPort[1:end]
		rest := hostPort[end+1:]
		if len(rest) > 0 && rest[0] == ':' {
			return host, rest[1:], nil
		}
		return host, "", nil
	}

	idx := strings.LastIndex(hostPort, ":")
	if idx < 0 {
		return hostPort, "", nil
	}
	return hostPort[:idx], hostPort[idx+1:], nil
}

// toInt 将 interface{} 转换为 int（支持字符串和数字）。
func toInt(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case string:
		n, _ := strconv.Atoi(val)
		return n
	case json.Number:
		n, _ := val.Int64()
		return int(n)
	default:
		return 0
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func boolQueryValue(query url.Values, keys ...string) bool {
	for _, key := range keys {
		raw := strings.TrimSpace(query.Get(key))
		if raw == "" {
			continue
		}
		value, err := strconv.ParseBool(raw)
		if err == nil {
			return value
		}
	}
	return false
}

// SaveToFile 将订阅内容保存到 ~/.forward/{basename}.yaml 文件中。
// 若来源是远程 URL，basename 取主机名；若来源是本地文件路径，basename 取文件名（去除扩展名）。
// 如果文件已存在，会自动添加后缀 -02、-03 等。
// 返回保存的文件路径。
func SaveToFile(data []byte, rawURL string) (string, error) {
	var baseName string

	if IsLocalPath(rawURL) {
		// 本地文件路径：使用文件名（去除扩展名）作为 baseName
		localPath := strings.TrimPrefix(rawURL, "file://")
		base := filepath.Base(localPath)
		ext := filepath.Ext(base)
		baseName = strings.TrimSuffix(base, ext)
		if baseName == "" || baseName == "." {
			baseName = "local-subscribe"
		}
	} else {
		// 远程 URL：使用主机名
		u, err := url.Parse(rawURL)
		if err != nil {
			return "", fmt.Errorf("解析 URL 失败: %w", err)
		}
		baseName = u.Hostname()
		if baseName == "" {
			return "", fmt.Errorf("无法从 URL 中提取主机名")
		}
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("获取用户主目录失败: %w", err)
	}

	dir := filepath.Join(homeDir, ".forward")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建目录 %s 失败: %w", dir, err)
	}

	filePath := filepath.Join(dir, baseName+".yaml")

	// 如果文件已存在，添加后缀
	if _, err := os.Stat(filePath); err == nil {
		for i := 2; ; i++ {
			suffix := fmt.Sprintf("-%02d", i)
			filePath = filepath.Join(dir, baseName+suffix+".yaml")
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				break
			}
		}
	}

	if err := os.WriteFile(filePath, data, 0o644); err != nil {
		return "", fmt.Errorf("保存订阅文件失败: %w", err)
	}
	return filePath, nil
}

// ProxyToEndpoint 将 ClashProxy 转换为项目使用的 endpoint.Endpoint。
func ProxyToEndpoint(p ClashProxy) (endpoint.Endpoint, error) {
	switch strings.ToLower(p.Type) {
	case "vmess":
		return vmessToEndpoint(p)
	case "ss", "shadowsocks":
		return ssToEndpoint(p)
	case "trojan":
		return trojanToEndpoint(p)
	case "vless":
		return vlesToEndpoint(p)
	case "hysteria2", "hy2":
		return hy2ToEndpoint(p)
	case "socks5", "socks5h":
		return socks5ToEndpoint(p)
	case "http", "https":
		return httpToEndpoint(p)
	default:
		return endpoint.Endpoint{}, fmt.Errorf("不支持的代理类型: %s", p.Type)
	}
}

// vmessToEndpoint 将 VMess 代理转换为 endpoint。
// 格式: vmess://security:uuid@server:port?alterId=N
func vmessToEndpoint(p ClashProxy) (endpoint.Endpoint, error) {
	security := p.Cipher
	if security == "" {
		security = "auto"
	}

	scheme := "vmess"
	if p.TLS {
		scheme = "vmess+tls"
	}
	if strings.EqualFold(p.Network, "ws") {
		scheme = "vmess" // WebSocket 通过 query 参数指定
	}

	// 构建 URL
	q := url.Values{}
	q.Set("alterId", strconv.Itoa(p.AlterID))

	if p.SNI != "" {
		q.Set("sni", p.SNI)
	}

	// WebSocket 传输
	if strings.EqualFold(p.Network, "ws") {
		q.Set("type", "ws")
		if p.WSOpts != nil {
			if p.WSOpts.Path != "" {
				q.Set("path", p.WSOpts.Path)
			}
			if host, ok := p.WSOpts.Headers["Host"]; ok {
				q.Set("host", host)
			}
		}
		if p.TLS {
			q.Set("security", "tls")
		}
	}

	rawURL := fmt.Sprintf("%s://%s:%s@%s:%d?%s",
		scheme,
		url.PathEscape(security),
		url.PathEscape(p.UUID),
		p.Server,
		p.Port,
		q.Encode(),
	)

	return endpoint.Parse(rawURL)
}

// ssToEndpoint 将 Shadowsocks 代理转换为 endpoint。
// 格式: ss://method:password@server:port?plugin=xxx&plugin_mode=xxx
func ssToEndpoint(p ClashProxy) (endpoint.Endpoint, error) {
	q := url.Values{}
	if p.Plugin != "" {
		q.Set("plugin", p.Plugin)
		if p.PluginOpts != nil {
			if mode, ok := p.PluginOpts["mode"].(string); ok {
				q.Set("plugin_mode", mode)
			}
			if host, ok := p.PluginOpts["host"].(string); ok {
				q.Set("plugin_host", host)
			}
		}
	}

	rawURL := fmt.Sprintf("ss://%s:%s@%s:%d",
		url.PathEscape(p.Cipher),
		url.PathEscape(p.Password),
		p.Server,
		p.Port,
	)
	if len(q) > 0 {
		rawURL += "?" + q.Encode()
	}
	return endpoint.Parse(rawURL)
}

// trojanToEndpoint 将 Trojan 代理转换为 endpoint。
// 格式: trojan://password@server:port?sni=xxx
func trojanToEndpoint(p ClashProxy) (endpoint.Endpoint, error) {
	q := url.Values{}
	if p.SNI != "" {
		q.Set("sni", p.SNI)
	}
	rawURL := fmt.Sprintf("trojan://%s@%s:%d",
		url.PathEscape(p.Password),
		p.Server,
		p.Port,
	)
	if len(q) > 0 {
		rawURL += "?" + q.Encode()
	}
	return endpoint.Parse(rawURL)
}

// vlesToEndpoint 将 VLESS 代理转换为 endpoint。
func vlesToEndpoint(p ClashProxy) (endpoint.Endpoint, error) {
	q := url.Values{}

	// SNI: 优先用 servername，其次 sni
	sni := p.ServerName
	if sni == "" {
		sni = p.SNI
	}
	if sni != "" {
		q.Set("sni", sni)
	}

	// Flow (e.g. xtls-rprx-vision)
	if p.Flow != "" {
		q.Set("flow", p.Flow)
	}

	// 指纹
	if p.ClientFingerprint != "" {
		q.Set("fp", p.ClientFingerprint)
	}
	if p.Mux {
		q.Set("mux", "true")
		if p.MuxMaxStreams > 0 {
			q.Set("mux_max_streams", strconv.Itoa(p.MuxMaxStreams))
		}
		if p.MuxIdle != "" {
			q.Set("mux_idle", p.MuxIdle)
		}
	}

	// 确定 scheme
	scheme := "vless"
	if p.RealityOpts != nil {
		// Reality 传输
		scheme = "vless+reality"
		if p.RealityOpts.PublicKey != "" {
			q.Set("pbk", p.RealityOpts.PublicKey)
		}
		if p.RealityOpts.ShortID != "" {
			q.Set("sid", p.RealityOpts.ShortID)
		}
		q.Set("security", "reality")
	} else if p.TLS {
		scheme = "vless+tls"
		q.Set("security", "tls")
	}

	// WebSocket 传输
	if strings.EqualFold(p.Network, "ws") {
		q.Set("type", "ws")
		if p.WSOpts != nil {
			if p.WSOpts.Path != "" {
				q.Set("path", p.WSOpts.Path)
			}
			if host, ok := p.WSOpts.Headers["Host"]; ok {
				q.Set("host", host)
			}
		}
		if p.TLS {
			q.Set("security", "tls")
		}
	}

	rawURL := fmt.Sprintf("%s://%s@%s:%d",
		scheme,
		url.PathEscape(p.UUID),
		p.Server,
		p.Port,
	)
	if len(q) > 0 {
		rawURL += "?" + q.Encode()
	}
	return endpoint.Parse(rawURL)
}

// hy2ToEndpoint 将 Hysteria2 代理转换为 endpoint。
func hy2ToEndpoint(p ClashProxy) (endpoint.Endpoint, error) {
	q := url.Values{}
	if p.SNI != "" {
		q.Set("sni", p.SNI)
	}
	if p.Insecure || p.SkipCert {
		q.Set("insecure", "1")
	}
	rawURL := fmt.Sprintf("hysteria2://%s@%s:%d",
		url.PathEscape(p.Password),
		p.Server,
		p.Port,
	)
	if len(q) > 0 {
		rawURL += "?" + q.Encode()
	}
	return endpoint.Parse(rawURL)
}

// socks5ToEndpoint 将 SOCKS5 代理转换为 endpoint。
// 格式: socks5://user:pass@server:port 或 socks5://server:port
func socks5ToEndpoint(p ClashProxy) (endpoint.Endpoint, error) {
	var rawURL string
	if p.Username != "" || p.Password != "" {
		rawURL = fmt.Sprintf("socks5://%s:%s@%s:%d",
			url.PathEscape(p.Username),
			url.PathEscape(p.Password),
			p.Server,
			p.Port,
		)
	} else {
		rawURL = fmt.Sprintf("socks5://%s:%d", p.Server, p.Port)
	}
	return endpoint.Parse(rawURL)
}

// httpToEndpoint 将 HTTP 代理转换为 endpoint。
// 格式: http://user:pass@server:port 或 http://server:port
func httpToEndpoint(p ClashProxy) (endpoint.Endpoint, error) {
	scheme := "http"
	if p.TLS || strings.EqualFold(p.Type, "https") {
		scheme = "https"
	}
	var rawURL string
	if p.Username != "" || p.Password != "" {
		rawURL = fmt.Sprintf("%s://%s:%s@%s:%d",
			scheme,
			url.PathEscape(p.Username),
			url.PathEscape(p.Password),
			p.Server,
			p.Port,
		)
	} else {
		rawURL = fmt.Sprintf("%s://%s:%d", scheme, p.Server, p.Port)
	}
	return endpoint.Parse(rawURL)
}
