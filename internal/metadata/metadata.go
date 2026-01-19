package metadata

import "strings"

type Metadata interface {
	IsExists(key string) bool
	Set(key string, value any)
	Get(key string) any
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
