// Package subscribe 实现订阅链接的下载、解析和管理。
// 支持 Clash YAML 和 base64 编码的代理 URI 列表两种格式。
package subscribe

import (
	"encoding/base64"
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

	"gopkg.in/yaml.v3"
)

// ClashConfig 表示 Clash 订阅 YAML 的顶层结构，仅关注 proxies 字段。
type ClashConfig struct {
	Proxies []ClashProxy `yaml:"proxies"`
}

// ClashProxy 表示 Clash 中的单个代理节点。
type ClashProxy struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`     // vmess, ss, trojan, vless, hysteria2 ...
	Server   string `yaml:"server"`   // 服务器地址
	Port     int    `yaml:"port"`     // 端口
	UUID     string `yaml:"uuid"`     // VMess/VLESS UUID
	AlterID  int    `yaml:"alterId"`  // VMess alterID
	Cipher   string `yaml:"cipher"`   // 加密方式
	UDP      bool   `yaml:"udp"`      // 是否支持 UDP
	Password string `yaml:"password"` // SS/Trojan 密码
	TLS      bool   `yaml:"tls"`      // 是否启用 TLS
	SNI      string `yaml:"sni"`      // TLS SNI
	Network  string `yaml:"network"`  // 传输网络 (ws, grpc 等)

	// WebSocket 选项
	WSOpts *WSOptions `yaml:"ws-opts,omitempty"`
}

// WSOptions 表示 WebSocket 传输选项。
type WSOptions struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
}

// Download 从指定 URL 下载订阅内容。
func Download(rawURL string) ([]byte, error) {
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

	return nil, fmt.Errorf("订阅内容格式无法识别（不是 Clash YAML 也不是 base64 编码的代理 URI 列表）")
}

// parseClashYAML 解析 Clash YAML 格式。
func parseClashYAML(data []byte) ([]ClashProxy, error) {
	var cfg ClashConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg.Proxies, nil
}

// tryBase64Decode 尝试 base64 解码，同时支持标准和 URL-safe 编码，以及有无 padding 的情况。
func tryBase64Decode(s string) ([]byte, error) {
	// 移除可能的空白字符
	s = strings.Join(strings.Fields(s), "")

	// 尝试标准 base64
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	// 尝试标准 base64 无 padding
	if decoded, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	// 尝试 URL-safe base64
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	// 尝试 URL-safe base64 无 padding
	if decoded, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return decoded, nil
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

// parseVmessURI 解析 vmess:// URI（base64 编码的 JSON）。
func parseVmessURI(uri string) (ClashProxy, error) {
	// vmess://base64EncodedJSON
	encoded := strings.TrimPrefix(uri, "vmess://")
	encoded = strings.TrimPrefix(encoded, "Vmess://")
	encoded = strings.TrimPrefix(encoded, "VMESS://")

	decoded, err := tryBase64Decode(encoded)
	if err != nil {
		return ClashProxy{}, fmt.Errorf("vmess URI base64 解码失败: %w", err)
	}

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

// parseVlessURI 解析 vless:// URI。
// 格式: vless://uuid@server:port?type=ws&security=tls&sni=xxx&path=/xxx#name
func parseVlessURI(uri string) (ClashProxy, error) {
	// 提取 fragment 作为节点名称
	name := ""
	if idx := strings.LastIndex(uri, "#"); idx >= 0 {
		name, _ = url.PathUnescape(uri[idx+1:])
		uri = uri[:idx]
	}

	u, err := url.Parse(uri)
	if err != nil {
		return ClashProxy{}, fmt.Errorf("vless URI 解析失败: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	uuid := u.User.Username()
	query := u.Query()

	proxy := ClashProxy{
		Name:    name,
		Type:    "vless",
		Server:  u.Hostname(),
		Port:    port,
		UUID:    uuid,
		TLS:     strings.EqualFold(query.Get("security"), "tls") || strings.EqualFold(query.Get("security"), "reality"),
		SNI:     query.Get("sni"),
		Network: query.Get("type"),
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
// 格式1: ss://base64(method:password)@server:port#name
// 格式2: ss://base64(method:password@server:port)#name
func parseSSURI(uri string) (ClashProxy, error) {
	name := ""
	if idx := strings.LastIndex(uri, "#"); idx >= 0 {
		name, _ = url.PathUnescape(uri[idx+1:])
		uri = uri[:idx]
	}

	content := strings.TrimPrefix(uri, "ss://")

	var method, password, server string
	var port int

	if atIdx := strings.LastIndex(content, "@"); atIdx >= 0 {
		// 格式1: base64(method:password)@server:port
		userInfoEncoded := content[:atIdx]
		hostPort := content[atIdx+1:]

		// 尝试 base64 解码 userinfo
		decoded, err := tryBase64Decode(userInfoEncoded)
		if err != nil {
			// 可能不是 base64，尝试直接解析
			decoded = []byte(userInfoEncoded)
		}

		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return ClashProxy{}, fmt.Errorf("ss URI userinfo 格式错误")
		}
		method = parts[0]
		password = parts[1]

		host, portStr, err := splitHostPort(hostPort)
		if err != nil {
			return ClashProxy{}, fmt.Errorf("ss URI host:port 解析失败: %w", err)
		}
		server = host
		port, _ = strconv.Atoi(portStr)
	} else {
		// 格式2: 整体 base64
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
		method = parts[0]
		password = parts[1]

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

	if proxy.Name == "" {
		proxy.Name = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
	}

	return proxy, nil
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
	name := ""
	if idx := strings.LastIndex(uri, "#"); idx >= 0 {
		name, _ = url.PathUnescape(uri[idx+1:])
		uri = uri[:idx]
	}

	u, err := url.Parse(uri)
	if err != nil {
		return ClashProxy{}, fmt.Errorf("hy2 URI 解析失败: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	password := u.User.Username()
	query := u.Query()

	proxy := ClashProxy{
		Name:     name,
		Type:     "hysteria2",
		Server:   u.Hostname(),
		Port:     port,
		Password: password,
		TLS:      true,
		SNI:      query.Get("sni"),
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

// SaveToFile 将订阅内容保存到 ~/.forward/{url-host}.yaml 文件中。
// 如果文件已存在，会自动添加后缀 -02、-03 等。
// 返回保存的文件路径。
func SaveToFile(data []byte, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("解析 URL 失败: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("无法从 URL 中提取主机名")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("获取用户主目录失败: %w", err)
	}

	dir := filepath.Join(homeDir, ".forward")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建目录 %s 失败: %w", dir, err)
	}

	baseName := host
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
// 格式: ss://method:password@server:port
func ssToEndpoint(p ClashProxy) (endpoint.Endpoint, error) {
	rawURL := fmt.Sprintf("ss://%s:%s@%s:%d",
		url.PathEscape(p.Cipher),
		url.PathEscape(p.Password),
		p.Server,
		p.Port,
	)
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
	if p.SNI != "" {
		q.Set("sni", p.SNI)
	}
	scheme := "vless"
	if p.TLS {
		scheme = "vless+tls"
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
