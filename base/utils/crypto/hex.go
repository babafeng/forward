package crypto

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateShortID(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}
