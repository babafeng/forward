// Package shadowsocks 提供 Shadowsocks 协议的编解码功能封装，支持传统 AEAD 和 2022 方法
package shadowsocks

import (
	"encoding/base64"
	"fmt"
	"strings"

	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
)

// 支持的加密方法（传统 AEAD + 2022）
var SupportedMethods = func() []string {
	all := make([]string, 0, len(shadowaead.List)+len(shadowaead_2022.List))
	all = append(all, shadowaead.List...)
	all = append(all, shadowaead_2022.List...)
	return all
}()

// Method 名称常量
const (
	MethodAES128GCM        = "2022-blake3-aes-128-gcm"
	MethodAES256GCM        = "2022-blake3-aes-256-gcm"
	MethodChacha20Poly1305 = "2022-blake3-chacha20-poly1305"
)

// Config Shadowsocks 配置
type Config struct {
	Method   string   // 加密方法
	Password string   // 原始密码字符串（可能包含多个 PSK，用 : 分隔）
	PSKList  [][]byte // 解析后的 PSK 列表
}

// ParseConfig 从加密方法和密码创建配置
func ParseConfig(method, password string) (*Config, error) {
	method = strings.ToLower(strings.TrimSpace(method))
	if !IsMethodSupported(method) {
		return nil, fmt.Errorf("unsupported shadowsocks method: %s", method)
	}

	if password == "" {
		return nil, fmt.Errorf("shadowsocks password is required")
	}

	// 仅 2022 方法需要解析多级 PSK
	if is2022Method(method) {
		pskList, err := ParsePSKList(password)
		if err != nil {
			return nil, fmt.Errorf("parse psk failed: %w", err)
		}
		return &Config{
			Method:   method,
			Password: password,
			PSKList:  pskList,
		}, nil
	}

	return &Config{
		Method:   method,
		Password: password,
	}, nil
}

// IsMethodSupported 检查加密方法是否支持
func IsMethodSupported(method string) bool {
	method = strings.ToLower(strings.TrimSpace(method))
	for _, m := range SupportedMethods {
		if m == method {
			return true
		}
	}
	return false
}

// ParsePSKList 解析 PSK 列表（支持多级密钥，用 : 分隔）
func ParsePSKList(password string) ([][]byte, error) {
	parts := strings.Split(password, ":")
	pskList := make([][]byte, len(parts))

	for i, part := range parts {
		psk, err := base64.StdEncoding.DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("decode psk[%d] failed: %w", i, err)
		}
		pskList[i] = psk
	}

	return pskList, nil
}

// KeySize 返回加密方法所需的密钥长度
func KeySize(method string) int {
	switch method {
	case MethodAES128GCM:
		return 16
	case MethodAES256GCM, MethodChacha20Poly1305:
		return 32
	default:
		return 0
	}
}

// NewMethod 创建 Shadowsocks 客户端 Method 实例
func NewMethod(method, password string) (shadowsocks.Method, error) {
	method = strings.ToLower(strings.TrimSpace(method))
	if !IsMethodSupported(method) {
		return nil, fmt.Errorf("unsupported shadowsocks method: %s", method)
	}
	// 传统 AEAD 方法使用 shadowaead.New（密码派生密钥）
	if isLegacyAEADMethod(method) {
		return shadowaead.New(method, nil, password)
	}
	// 2022 方法使用 shadowaead_2022.NewWithPassword
	return shadowaead_2022.NewWithPassword(method, password, nil)
}

// is2022Method 判断是否为 Shadowsocks 2022 方法
func is2022Method(method string) bool {
	for _, m := range shadowaead_2022.List {
		if m == method {
			return true
		}
	}
	return false
}

// isLegacyAEADMethod 判断是否为传统 AEAD 方法
func isLegacyAEADMethod(method string) bool {
	for _, m := range shadowaead.List {
		if m == method {
			return true
		}
	}
	return false
}

// NewService 创建 Shadowsocks 服务端 Service 实例
// handler 需要实现 shadowsocks.Handler 接口
// password 支持多级 PSK 格式：iPSK:uPSK（用 : 分隔）
func NewService(method, password string, udpTimeout int64, handler shadowsocks.Handler) (shadowsocks.Service, error) {
	if !IsMethodSupported(method) {
		return nil, fmt.Errorf("unsupported shadowsocks method: %s", method)
	}

	// 检查是否是多级 PSK 格式（包含 :）
	if strings.Contains(password, ":") {
		// 多级 PSK：格式为 iPSK:uPSK
		// 使用 MultiService 来处理
		parts := strings.SplitN(password, ":", 2)
		iPSK := parts[0]
		uPSK := parts[1]

		// 创建 MultiService（使用 iPSK）
		service, err := shadowaead_2022.NewMultiServiceWithPassword[string](method, iPSK, udpTimeout, handler, nil)
		if err != nil {
			return nil, fmt.Errorf("create shadowsocks multi service failed: %w", err)
		}

		// 注册用户 PSK
		err = service.UpdateUsersWithPasswords([]string{"default"}, []string{uPSK})
		if err != nil {
			return nil, fmt.Errorf("update shadowsocks user failed: %w", err)
		}

		return service, nil
	}

	// 单 PSK：直接使用 Service
	return shadowaead_2022.NewServiceWithPassword(method, password, udpTimeout, handler, nil)
}
