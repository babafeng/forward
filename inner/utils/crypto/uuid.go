package crypto

import (
	"crypto/rand"
	"fmt"
)

func GenerateUUID() string {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return ""
	}
	// version 4
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// variant
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
