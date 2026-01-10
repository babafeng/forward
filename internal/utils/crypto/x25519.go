package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
)

func GenerateX25519Keys() (string, string, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	privBytes := privKey.Bytes()
	pubBytes := privKey.PublicKey().Bytes()

	privBase64 := base64.RawURLEncoding.EncodeToString(privBytes)
	pubBase64 := base64.RawURLEncoding.EncodeToString(pubBytes)

	return privBase64, pubBase64, nil
}

func GetPublicKey(privKeyBase64 string) (string, error) {
	privBytes, err := base64.RawURLEncoding.DecodeString(privKeyBase64)
	if err != nil {
		return "", err
	}

	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return "", err
	}

	pubBytes := priv.PublicKey().Bytes()
	return base64.RawURLEncoding.EncodeToString(pubBytes), nil
}
