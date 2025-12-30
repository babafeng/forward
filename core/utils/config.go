package utils

import "sync/atomic"

var (
	insecureSkipVerify atomic.Bool
)

func SetInsecure(insecure bool) {
	if insecure {
		Warn("SSL/TLS insecure skip verify enabled")
	}
	insecureSkipVerify.Store(insecure)
}

func GetInsecure() bool {
	return insecureSkipVerify.Load()
}
