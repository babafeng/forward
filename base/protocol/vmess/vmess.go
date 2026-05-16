// Package vmess 提供 VMess 协议的编解码功能封装
package vmess

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	xuuid "github.com/xtls/xray-core/common/uuid"
	xvmess "github.com/xtls/xray-core/proxy/vmess"
)

// 加密方式常量
const (
	SecurityAuto             = "auto"
	SecurityAES128GCM        = "aes-128-gcm"
	SecurityChacha20Poly1305 = "chacha20-poly1305"
	SecurityNone             = "none"
)

// SecurityType 加密类型
type SecurityType byte

const (
	SecurityTypeUnknown          SecurityType = 0
	SecurityTypeLegacy           SecurityType = 1
	SecurityTypeAuto             SecurityType = 2
	SecurityTypeAES128GCM        SecurityType = 3
	SecurityTypeChacha20Poly1305 SecurityType = 4
	SecurityTypeNone             SecurityType = 5
	SecurityTypeZero             SecurityType = 6
)

// ParseSecurityType 解析加密类型字符串
func ParseSecurityType(s string) SecurityType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return SecurityTypeAuto
	case "aes-128-gcm":
		return SecurityTypeAES128GCM
	case "chacha20-poly1305":
		return SecurityTypeChacha20Poly1305
	case "none":
		return SecurityTypeNone
	case "zero":
		return SecurityTypeZero
	default:
		return SecurityTypeAuto
	}
}

// ToXraySecurity 转换为 xray-core 的 SecurityType
func (s SecurityType) ToXraySecurity() protocol.SecurityType {
	switch s {
	case SecurityTypeAES128GCM:
		return protocol.SecurityType_AES128_GCM
	case SecurityTypeChacha20Poly1305:
		return protocol.SecurityType_CHACHA20_POLY1305
	case SecurityTypeNone:
		return protocol.SecurityType_NONE
	case SecurityTypeZero:
		return protocol.SecurityType_ZERO
	case SecurityTypeAuto:
		return protocol.SecurityType_AUTO
	default:
		return protocol.SecurityType_AUTO
	}
}

// UUID 表示 VMess UUID
type UUID [16]byte

// ParseUUID 解析 UUID 字符串
func ParseUUID(s string) (UUID, error) {
	var u UUID
	clean := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '-' {
			clean = append(clean, byte(c))
		}
	}
	if len(clean) != 32 {
		return u, fmt.Errorf("invalid uuid length: %d", len(clean))
	}
	_, err := hex.Decode(u[:], clean)
	return u, err
}

// String 返回 UUID 的标准格式字符串
func (u UUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// ToXrayUUID 转换为 xray-core 的 UUID
func (u UUID) ToXrayUUID() (xuuid.UUID, error) {
	return xuuid.ParseBytes(u[:])
}

// UserConfig 用户配置
type UserConfig struct {
	UUID     string
	AlterID  int
	Security SecurityType
}

// CreateUser 创建 xray-core 用户
func CreateUser(cfg UserConfig) (*protocol.MemoryUser, error) {
	uuid, err := ParseUUID(cfg.UUID)
	if err != nil {
		return nil, fmt.Errorf("invalid vmess uuid: %w", err)
	}

	xid, err := uuid.ToXrayUUID()
	if err != nil {
		return nil, fmt.Errorf("convert uuid failed: %w", err)
	}

	account := &xvmess.MemoryAccount{
		ID:       protocol.NewID(xid),
		Security: cfg.Security.ToXraySecurity(),
	}

	return &protocol.MemoryUser{
		Account: account,
		Email:   cfg.UUID,
	}, nil
}

// CreateValidator 创建用户验证器
func CreateValidator(users ...UserConfig) (*xvmess.TimedUserValidator, error) {
	validator := xvmess.NewTimedUserValidator()

	for _, cfg := range users {
		user, err := CreateUser(cfg)
		if err != nil {
			return nil, err
		}
		if err := validator.Add(user); err != nil {
			return nil, fmt.Errorf("add user failed: %w", err)
		}
	}

	return validator, nil
}

// GenerateCmdKey 生成 VMess 命令密钥
func GenerateCmdKey(id *protocol.ID) []byte {
	idBytes := id.Bytes()
	idHash := md5.New()
	idHash.Write(idBytes)
	idHash.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	return idHash.Sum(nil)
}

// TimestampGenerator 时间戳生成器
type TimestampGenerator func() protocol.Timestamp

// DefaultTimestampGenerator 默认时间戳生成器
func DefaultTimestampGenerator() protocol.Timestamp {
	return protocol.Timestamp(time.Now().Unix())
}
