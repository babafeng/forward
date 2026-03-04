package subscribe

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestParseClashYAML(t *testing.T) {
	yamlData := `
proxies:
  - name: "test-vmess"
    type: vmess
    server: example.com
    port: 443
    uuid: "uuid-1234"
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: example.com
  - name: "test-ss"
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: "mypassword"
`
	proxies, err := Parse([]byte(yamlData))
	if err != nil {
		t.Fatalf("解析 Clash YAML 失败: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("期望 2 个节点，得到 %d 个", len(proxies))
	}
	if proxies[0].Name != "test-vmess" {
		t.Errorf("期望节点名称 'test-vmess'，得到 '%s'", proxies[0].Name)
	}
	if proxies[0].Type != "vmess" {
		t.Errorf("期望类型 'vmess'，得到 '%s'", proxies[0].Type)
	}
	if proxies[0].Server != "example.com" {
		t.Errorf("期望服务器 'example.com'，得到 '%s'", proxies[0].Server)
	}
	if proxies[1].Name != "test-ss" {
		t.Errorf("期望节点名称 'test-ss'，得到 '%s'", proxies[1].Name)
	}
}

func TestParseBase64URIList(t *testing.T) {
	// 构建一组代理 URI
	vmessJSON := map[string]interface{}{
		"v":    "2",
		"ps":   "US Node",
		"add":  "us1.example.com",
		"port": 443,
		"id":   "uuid-abcd-1234",
		"aid":  0,
		"net":  "ws",
		"type": "none",
		"host": "us1.example.com",
		"path": "/ws",
		"tls":  "tls",
		"sni":  "us1.example.com",
	}
	vmessJSONBytes, _ := json.Marshal(vmessJSON)
	vmessURI := "vmess://" + base64.StdEncoding.EncodeToString(vmessJSONBytes)

	trojanURI := "trojan://mypassword@trojan.example.com:443?sni=trojan.example.com#Trojan%20Node"
	ssURI := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:sspassword")) + "@ss.example.com:8388#SS%20Node"

	uriList := vmessURI + "\n" + trojanURI + "\n" + ssURI + "\n"

	// Base64 编码整个 URI 列表
	encoded := base64.StdEncoding.EncodeToString([]byte(uriList))

	proxies, err := Parse([]byte(encoded))
	if err != nil {
		t.Fatalf("解析 base64 URI 列表失败: %v", err)
	}
	if len(proxies) != 3 {
		t.Fatalf("期望 3 个节点，得到 %d 个", len(proxies))
	}

	// 验证 vmess 节点
	if proxies[0].Type != "vmess" {
		t.Errorf("期望类型 'vmess'，得到 '%s'", proxies[0].Type)
	}
	if proxies[0].Name != "US Node" {
		t.Errorf("期望名称 'US Node'，得到 '%s'", proxies[0].Name)
	}
	if proxies[0].Server != "us1.example.com" {
		t.Errorf("期望服务器 'us1.example.com'，得到 '%s'", proxies[0].Server)
	}
	if proxies[0].Port != 443 {
		t.Errorf("期望端口 443，得到 %d", proxies[0].Port)
	}
	if proxies[0].UUID != "uuid-abcd-1234" {
		t.Errorf("期望 UUID 'uuid-abcd-1234'，得到 '%s'", proxies[0].UUID)
	}
	if !proxies[0].TLS {
		t.Error("期望 TLS 为 true")
	}
	if proxies[0].Network != "ws" {
		t.Errorf("期望网络 'ws'，得到 '%s'", proxies[0].Network)
	}
	if proxies[0].WSOpts == nil {
		t.Error("期望 WSOpts 不为 nil")
	} else {
		if proxies[0].WSOpts.Path != "/ws" {
			t.Errorf("期望 WS path '/ws'，得到 '%s'", proxies[0].WSOpts.Path)
		}
	}

	// 验证 trojan 节点
	if proxies[1].Type != "trojan" {
		t.Errorf("期望类型 'trojan'，得到 '%s'", proxies[1].Type)
	}
	if proxies[1].Name != "Trojan Node" {
		t.Errorf("期望名称 'Trojan Node'，得到 '%s'", proxies[1].Name)
	}
	if proxies[1].Password != "mypassword" {
		t.Errorf("期望密码 'mypassword'，得到 '%s'", proxies[1].Password)
	}

	// 验证 ss 节点
	if proxies[2].Type != "ss" {
		t.Errorf("期望类型 'ss'，得到 '%s'", proxies[2].Type)
	}
	if proxies[2].Name != "SS Node" {
		t.Errorf("期望名称 'SS Node'，得到 '%s'", proxies[2].Name)
	}
	if proxies[2].Cipher != "aes-256-gcm" {
		t.Errorf("期望加密方式 'aes-256-gcm'，得到 '%s'", proxies[2].Cipher)
	}
	if proxies[2].Password != "sspassword" {
		t.Errorf("期望密码 'sspassword'，得到 '%s'", proxies[2].Password)
	}
}

func TestParseVmessURI(t *testing.T) {
	v := vmessJSON{
		V:    "2",
		PS:   "🇺🇲 美国节点",
		Add:  "us.example.com",
		Port: "8443",
		ID:   "test-uuid-1234",
		Aid:  "0",
		Net:  "ws",
		Type: "none",
		Host: "cdn.example.com",
		Path: "/vmess",
		TLS:  "tls",
		SNI:  "cdn.example.com",
		Scy:  "aes-128-gcm",
	}
	jsonBytes, _ := json.Marshal(v)
	uri := "vmess://" + base64.StdEncoding.EncodeToString(jsonBytes)

	proxy, err := parseVmessURI(uri)
	if err != nil {
		t.Fatalf("解析 vmess URI 失败: %v", err)
	}

	if proxy.Name != "🇺🇲 美国节点" {
		t.Errorf("期望名称 '🇺🇲 美国节点'，得到 '%s'", proxy.Name)
	}
	if proxy.Server != "us.example.com" {
		t.Errorf("期望服务器 'us.example.com'，得到 '%s'", proxy.Server)
	}
	if proxy.Port != 8443 {
		t.Errorf("期望端口 8443，得到 %d", proxy.Port)
	}
	if proxy.UUID != "test-uuid-1234" {
		t.Errorf("期望 UUID 'test-uuid-1234'，得到 '%s'", proxy.UUID)
	}
	if proxy.Cipher != "aes-128-gcm" {
		t.Errorf("期望加密方式 'aes-128-gcm'，得到 '%s'", proxy.Cipher)
	}
	if !proxy.TLS {
		t.Error("期望 TLS 为 true")
	}
	if proxy.SNI != "cdn.example.com" {
		t.Errorf("期望 SNI 'cdn.example.com'，得到 '%s'", proxy.SNI)
	}
	if proxy.WSOpts == nil {
		t.Fatal("期望 WSOpts 不为 nil")
	}
	if proxy.WSOpts.Path != "/vmess" {
		t.Errorf("期望 WS path '/vmess'，得到 '%s'", proxy.WSOpts.Path)
	}
	if proxy.WSOpts.Headers["Host"] != "cdn.example.com" {
		t.Errorf("期望 WS host 'cdn.example.com'，得到 '%s'", proxy.WSOpts.Headers["Host"])
	}
}

func TestParsePlainURIList(t *testing.T) {
	uriList := `
trojan://password123@trojan.test.com:443?sni=trojan.test.com#Test%20Trojan
vless://uuid-5678@vless.test.com:443?type=ws&security=tls&sni=vless.test.com&path=/vless#Test%20VLESS
hy2://hypass@hy2.test.com:443?sni=hy2.test.com#Test%20HY2
`
	proxies, err := Parse([]byte(uriList))
	if err != nil {
		t.Fatalf("解析纯文本 URI 列表失败: %v", err)
	}
	if len(proxies) != 3 {
		t.Fatalf("期望 3 个节点，得到 %d 个", len(proxies))
	}

	// Trojan
	if proxies[0].Type != "trojan" {
		t.Errorf("期望类型 'trojan'，得到 '%s'", proxies[0].Type)
	}
	if proxies[0].Name != "Test Trojan" {
		t.Errorf("期望名称 'Test Trojan'，得到 '%s'", proxies[0].Name)
	}
	if proxies[0].Password != "password123" {
		t.Errorf("期望密码 'password123'，得到 '%s'", proxies[0].Password)
	}
	if !proxies[0].TLS {
		t.Error("Trojan 节点期望 TLS 为 true")
	}

	// VLESS
	if proxies[1].Type != "vless" {
		t.Errorf("期望类型 'vless'，得到 '%s'", proxies[1].Type)
	}
	if proxies[1].Name != "Test VLESS" {
		t.Errorf("期望名称 'Test VLESS'，得到 '%s'", proxies[1].Name)
	}
	if proxies[1].UUID != "uuid-5678" {
		t.Errorf("期望 UUID 'uuid-5678'，得到 '%s'", proxies[1].UUID)
	}
	if proxies[1].Network != "ws" {
		t.Errorf("期望网络 'ws'，得到 '%s'", proxies[1].Network)
	}

	// HY2
	if proxies[2].Type != "hysteria2" {
		t.Errorf("期望类型 'hysteria2'，得到 '%s'", proxies[2].Type)
	}
	if proxies[2].Name != "Test HY2" {
		t.Errorf("期望名称 'Test HY2'，得到 '%s'", proxies[2].Name)
	}
	if proxies[2].Password != "hypass" {
		t.Errorf("期望密码 'hypass'，得到 '%s'", proxies[2].Password)
	}
}

func TestParseBase64NoPadding(t *testing.T) {
	// 使用无 padding 的 base64 编码
	trojanURI := "trojan://testpass@server.com:443?sni=server.com#TestNode\n"
	encoded := base64.RawStdEncoding.EncodeToString([]byte(trojanURI))

	proxies, err := Parse([]byte(encoded))
	if err != nil {
		t.Fatalf("解析无 padding base64 失败: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("期望 1 个节点，得到 %d 个", len(proxies))
	}
	if proxies[0].Type != "trojan" {
		t.Errorf("期望类型 'trojan'，得到 '%s'", proxies[0].Type)
	}
	if proxies[0].Name != "TestNode" {
		t.Errorf("期望名称 'TestNode'，得到 '%s'", proxies[0].Name)
	}
}
