// Package subscribe 实现 Clash 格式订阅链接的下载、解析和管理。
package subscribe

import (
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

// Parse 解析 Clash YAML 格式的订阅数据为代理节点列表。
func Parse(data []byte) ([]ClashProxy, error) {
	var cfg ClashConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析订阅 YAML 失败: %w", err)
	}
	if len(cfg.Proxies) == 0 {
		return nil, fmt.Errorf("订阅内容中未找到代理节点")
	}
	return cfg.Proxies, nil
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
