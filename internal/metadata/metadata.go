package metadata

import "strings"

// Metadata key 常量
const (
	KeyHost        = "host"
	KeyPort        = "port"
	KeySecurity    = "security"
	KeyNetwork     = "network"
	KeySNI         = "sni"
	KeyFingerprint = "fingerprint"
	KeyPublicKey   = "pbk"
	KeyShortID     = "sid"
	KeySpiderX     = "spiderx"
	KeyALPN        = "alpn"
	KeyInsecure    = "insecure"
	KeyFlow        = "flow"
	KeyEncryption  = "encryption"
	KeyUUID        = "uuid"
	KeyAlterID     = "alterid"
	KeyOriginalDst = "original_dst"
	KeyPath        = "path"
)

type Metadata interface {
	IsExists(key string) bool
	Set(key string, value any)
	Get(key string) any
	GetString(key string) string
	GetInt(key string) int
	GetBool(key string) bool
}

type mapMetadata map[string]any

func New(m map[string]any) Metadata {
	if m == nil {
		return nil
	}
	md := make(map[string]any)
	for k, v := range m {
		md[strings.ToLower(k)] = v
	}
	return mapMetadata(md)
}

func (m mapMetadata) IsExists(key string) bool {
	_, ok := m[strings.ToLower(key)]
	return ok
}

func (m mapMetadata) Set(key string, value any) {
	m[strings.ToLower(key)] = value
}

func (m mapMetadata) Get(key string) any {
	if m != nil {
		return m[strings.ToLower(key)]
	}
	return nil
}

func (m mapMetadata) GetString(key string) string {
	v := m.Get(key)
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (m mapMetadata) GetInt(key string) int {
	v := m.Get(key)
	if v == nil {
		return 0
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func (m mapMetadata) GetBool(key string) bool {
	v := m.Get(key)
	if v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	if s, ok := v.(string); ok {
		return strings.ToLower(s) == "true" || s == "1"
	}
	return false
}
