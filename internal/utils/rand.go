package utils

import (
	"crypto/rand"
	"encoding/hex"
)

func NewID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}
